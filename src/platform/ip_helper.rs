//! Decoding for the records Windows' IP Helper API returns: adapters with
//! their addresses, DNS servers and gateways, per-interface counters, and the
//! routing table. Platform-neutral so the decoding is unit-tested on every
//! host; only the calls that fill these structs (`platform::windows`) are
//! Windows-only, as with `npcap_device`.
//!
//! The structs are the fields netwatch reads, copied out of the windows-sys
//! records while the API's buffer is alive, so nothing here touches a raw
//! pointer and every decision made from them can be tested with literals.

use super::{InterfaceInfo, InterfaceStats};
use std::collections::HashMap;
use std::net::{IpAddr, Ipv4Addr, Ipv6Addr};

/// Windows' address-family numbers. `AF_INET6` is 23 there, not the 10 Linux
/// uses, so they are spelled out here; the Windows module holds them to the
/// windows-sys values at compile time.
pub const AF_INET: u16 = 2;
pub const AF_INET6: u16 = 23;

/// `IF_TYPE_*` from ipifcons.h, held to windows-sys the same way.
pub const IF_TYPE_ETHERNET_CSMACD: u32 = 6;
pub const IF_TYPE_SOFTWARE_LOOPBACK: u32 = 24;
pub const IF_TYPE_IEEE80211: u32 = 71;

/// One `IP_ADAPTER_ADDRESSES_LH` record, as far as netwatch reads it. The
/// address lists are empty when the call was told to skip them.
#[derive(Debug, Clone, Default, PartialEq)]
pub struct Adapter {
    /// The `NET_LUID`, which is how the interface and route tables refer to
    /// this adapter.
    pub luid: u64,
    /// `AdapterName`: the interface GUID in braces, which is what Npcap's
    /// `\Device\NPF_{GUID}` device name carries.
    pub guid: String,
    /// `FriendlyName`, the name ipconfig and Get-NetAdapter show.
    pub name: String,
    pub if_type: u32,
    pub is_up: bool,
    pub mtu: u32,
    pub mac: Vec<u8>,
    pub unicast: Vec<IpAddr>,
    pub dns_servers: Vec<IpAddr>,
    pub gateways: Vec<IpAddr>,
    /// Interface metrics. Windows ranks a route by its own metric plus the
    /// interface's, so a route's metric alone does not say which one wins.
    pub ipv4_metric: u32,
    pub ipv6_metric: u32,
}

impl Adapter {
    /// Whether this is one of the adapters ipconfig listed: loopback excluded,
    /// and a record without a friendly name skipped. Interface info, counters
    /// and GUIDs all key on the same set, so the Interfaces tab can join them
    /// by name.
    pub fn listed(&self) -> bool {
        self.if_type != IF_TYPE_SOFTWARE_LOOPBACK && !self.name.is_empty()
    }
}

/// The address in a Windows `SOCKADDR`, given its bytes. `sockaddr_in` keeps
/// it at byte 4, `sockaddr_in6` at byte 8.
///
/// The IPv6 scope id is dropped: the DNS and gateway probes and Diagnose all
/// parse addresses with `IpAddr::from_str`, which rejects a zone index.
pub fn sockaddr_ip(raw: &[u8]) -> Option<IpAddr> {
    let family = u16::from_ne_bytes(raw.get(..2)?.try_into().ok()?);
    match family {
        AF_INET => {
            let b: [u8; 4] = raw.get(4..8)?.try_into().ok()?;
            Some(IpAddr::V4(Ipv4Addr::from(b)))
        }
        AF_INET6 => {
            let b: [u8; 16] = raw.get(8..24)?.try_into().ok()?;
            Some(IpAddr::V6(Ipv6Addr::from(b)))
        }
        _ => None,
    }
}

/// The interface list entry for a listed adapter, `None` for one ipconfig
/// did not list.
pub fn interface_info(a: &Adapter) -> Option<InterfaceInfo> {
    if !a.listed() {
        return None;
    }
    let mut v4 = Vec::new();
    let mut v6 = Vec::new();
    // A disconnected adapter keeps a stale or 169.254 autoconfig address the
    // API still reports; ipconfig showed none, and the address is a
    // capture-matching fallback, so report it only while the link is up.
    if a.is_up {
        for ip in &a.unicast {
            match ip {
                IpAddr::V4(ip) => v4.push(*ip),
                IpAddr::V6(ip) => v6.push(*ip),
            }
        }
    }
    Some(InterfaceInfo {
        name: a.name.clone(),
        ipv4: v4.first().map(|ip| ip.to_string()),
        ipv6: pick_ipv6(&v6).map(|ip| ip.to_string()),
        mac: format_mac(&a.mac),
        mtu: (a.mtu != 0 && a.mtu != u32::MAX).then_some(a.mtu),
        is_up: a.is_up,
        is_wireless: wireless_from_if_type(a.if_type),
    })
}

/// The preference ipconfig's ordering gave the old parser: a routable address
/// over the link-local one every adapter carries.
fn pick_ipv6(addrs: &[Ipv6Addr]) -> Option<Ipv6Addr> {
    addrs
        .iter()
        .find(|ip| !is_link_local_v6(ip))
        .or_else(|| addrs.first())
        .copied()
}

fn is_link_local_v6(ip: &Ipv6Addr) -> bool {
    (ip.segments()[0] & 0xffc0) == 0xfe80
}

/// `AA:BB:CC:DD:EE:FF`, the form the ipconfig parser produced.
fn format_mac(bytes: &[u8]) -> Option<String> {
    if bytes.is_empty() || bytes.iter().all(|b| *b == 0) {
        return None;
    }
    Some(
        bytes
            .iter()
            .map(|b| format!("{b:02X}"))
            .collect::<Vec<_>>()
            .join(":"),
    )
}

/// Wi-Fi is IEEE 802.11 and wired is Ethernet CSMA/CD; tunnels, VPNs and the
/// rest stay unknown, as `InterfaceInfo::is_wireless` documents.
fn wireless_from_if_type(if_type: u32) -> Option<bool> {
    match if_type {
        IF_TYPE_IEEE80211 => Some(true),
        IF_TYPE_ETHERNET_CSMACD => Some(false),
        _ => None,
    }
}

/// Friendly name -> interface GUID for the listed adapters: the bridge from
/// the names the interface list shows to the device Npcap opens (issue #51).
/// Should two records share a name, the first keeps it.
pub fn adapter_guids(adapters: &[Adapter]) -> HashMap<String, String> {
    let mut guids = HashMap::new();
    for a in adapters {
        if a.listed() && !a.guid.trim().is_empty() {
            guids
                .entry(a.name.clone())
                .or_insert_with(|| a.guid.trim().to_string());
        }
    }
    guids
}

/// The text netwatch keeps for a DNS server address, or `None` for one to
/// drop.
///
/// An adapter with IPv6 enabled and no IPv6 resolver configured reports
/// `fec0:0:0:ffff::1`, `::2` and `::3`. Those are site-local anycast
/// addresses, deprecated by RFC 3879 in 2004, and nothing answers them on a
/// normal network. ipconfig prints them, and a probe sent there would report
/// 100% loss to a resolver the host never uses. Go's resolver drops the same
/// range for the same reason.
pub fn dns_server_text(ip: IpAddr) -> Option<String> {
    match ip {
        IpAddr::V6(v6) if (v6.segments()[0] & 0xffc0) == 0xfec0 => None,
        ip if ip.is_unspecified() => None,
        ip => Some(ip.to_string()),
    }
}

/// DNS servers in the order netwatch should try them, each once, from the
/// adapters that are up: the default-route adapter's first, because the
/// Health probe takes the first and that adapter carries the host's traffic,
/// then those of other adapters with a gateway, then the rest. Within each
/// group the API's own order is kept.
pub fn dns_servers(adapters: &[Adapter], default_luid: Option<u64>) -> Vec<String> {
    let rank = |a: &Adapter| {
        if Some(a.luid) == default_luid {
            0
        } else if !a.gateways.is_empty() {
            1
        } else {
            2
        }
    };
    let mut up: Vec<&Adapter> = adapters.iter().filter(|a| a.listed() && a.is_up).collect();
    up.sort_by_key(|a| rank(a));
    let mut out: Vec<String> = Vec::new();
    for ip in up.iter().flat_map(|a| a.dns_servers.iter()) {
        if let Some(text) = dns_server_text(*ip) {
            if !out.contains(&text) {
                out.push(text);
            }
        }
    }
    out
}

/// The `MIB_IF_ROW2` counters netwatch reads.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq)]
pub struct IfCounters {
    pub in_octets: u64,
    pub in_ucast_pkts: u64,
    pub in_nucast_pkts: u64,
    pub in_discards: u64,
    pub in_errors: u64,
    pub out_octets: u64,
    pub out_ucast_pkts: u64,
    pub out_nucast_pkts: u64,
    pub out_discards: u64,
    pub out_errors: u64,
}

/// One interface's counters as `InterfaceStats`.
///
/// Packets are unicast plus non-unicast, which is what Linux's
/// `/proc/net/dev` and the BSDs' `netstat -i` count. The PowerShell path this
/// replaces read unicast only, so broadcast and multicast (ARP, mDNS, SSDP)
/// went missing from the Windows totals.
pub fn interface_stats(name: &str, c: &IfCounters) -> InterfaceStats {
    InterfaceStats {
        name: name.to_string(),
        rx_bytes: c.in_octets,
        tx_bytes: c.out_octets,
        rx_packets: c.in_ucast_pkts.saturating_add(c.in_nucast_pkts),
        tx_packets: c.out_ucast_pkts.saturating_add(c.out_nucast_pkts),
        rx_errors: c.in_errors,
        tx_errors: c.out_errors,
        rx_drops: c.in_discards,
        tx_drops: c.out_discards,
        signal_dbm: None,
        tx_retries: None,
    }
}

/// Counters keyed by friendly name for the listed adapters, joined on LUID.
///
/// The interface table also holds rows ipconfig never showed (the NDIS filter
/// and WAN miniport interfaces), so it is the adapter list that decides which
/// names appear, as Get-NetAdapterStatistics did.
pub fn stats_by_name(
    adapters: &[Adapter],
    counters: &HashMap<u64, IfCounters>,
) -> HashMap<String, InterfaceStats> {
    adapters
        .iter()
        .filter(|a| a.listed())
        .filter_map(|a| {
            let c = counters.get(&a.luid)?;
            Some((a.name.clone(), interface_stats(&a.name, c)))
        })
        .collect()
}

/// One `MIB_IPFORWARD_ROW2`, as far as netwatch reads it.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Route {
    pub luid: u64,
    pub destination: IpAddr,
    pub prefix_len: u8,
    /// The unspecified address for an on-link route.
    pub next_hop: IpAddr,
    /// The route's own metric, before the interface's is added.
    pub metric: u32,
}

/// A default route, with the adapter carrying it.
#[derive(Debug, Clone, Copy, PartialEq)]
pub struct DefaultRoute<'a> {
    pub adapter: &'a Adapter,
    /// `None` for an on-link default, such as a VPN's.
    pub next_hop: Option<IpAddr>,
    /// Route metric plus interface metric.
    pub metric: u64,
}

/// The default routes (0.0.0.0/0 and ::/0) on listed adapters that are up,
/// best first.
///
/// IPv4 comes before IPv6: the PowerShell lookup this replaces asked for IPv4
/// only, as Linux's `ip route` and macOS's `netstat -rn` answer first, so
/// IPv6 decides only on a host with no IPv4 default. Within a family the
/// lowest route-plus-interface metric wins, which is how Windows picks.
pub fn default_routes<'a>(routes: &[Route], adapters: &'a [Adapter]) -> Vec<DefaultRoute<'a>> {
    let mut out: Vec<(bool, DefaultRoute<'a>)> = routes
        .iter()
        .filter(|r| r.prefix_len == 0 && r.destination.is_unspecified())
        .filter_map(|r| {
            let adapter = adapters
                .iter()
                .find(|a| a.luid == r.luid && a.listed() && a.is_up)?;
            let ipv6 = r.destination.is_ipv6();
            let if_metric = if ipv6 {
                adapter.ipv6_metric
            } else {
                adapter.ipv4_metric
            };
            Some((
                ipv6,
                DefaultRoute {
                    adapter,
                    next_hop: (!r.next_hop.is_unspecified()).then_some(r.next_hop),
                    metric: u64::from(r.metric) + u64::from(if_metric),
                },
            ))
        })
        .collect();
    out.sort_by_key(|(ipv6, r)| (*ipv6, r.metric));
    out.into_iter().map(|(_, r)| r).collect()
}

/// The default gateway: the next hop of the best default route that has one.
///
/// An on-link default has no next hop to probe. An IPv6 link-local next hop
/// (`fe80::1`, the usual one) is skipped as well: reaching it needs a zone
/// index, and the gateway probe and Diagnose parse the address without one.
pub fn default_gateway(routes: &[DefaultRoute]) -> Option<String> {
    routes
        .iter()
        .filter_map(|r| r.next_hop)
        .find(|ip| match ip {
            IpAddr::V4(_) => true,
            IpAddr::V6(v6) => !is_link_local_v6(v6),
        })
        .map(|ip| ip.to_string())
}

#[cfg(test)]
mod tests {
    use super::*;

    fn v4(s: &str) -> IpAddr {
        IpAddr::V4(s.parse().unwrap())
    }

    fn v6(s: &str) -> IpAddr {
        IpAddr::V6(s.parse().unwrap())
    }

    fn adapter(luid: u64, name: &str) -> Adapter {
        Adapter {
            luid,
            guid: format!("{{0000000{luid}-0000-0000-0000-000000000000}}"),
            name: name.into(),
            if_type: IF_TYPE_ETHERNET_CSMACD,
            is_up: true,
            mtu: 1500,
            ..Adapter::default()
        }
    }

    fn default_route(luid: u64, next_hop: IpAddr, metric: u32) -> Route {
        let destination = match next_hop {
            IpAddr::V4(_) => v4("0.0.0.0"),
            IpAddr::V6(_) => v6("::"),
        };
        Route {
            luid,
            destination,
            prefix_len: 0,
            next_hop,
            metric,
        }
    }

    #[test]
    fn prefers_routable_ipv6_over_link_local() {
        let ll: Ipv6Addr = "fe80::1".parse().unwrap();
        let global: Ipv6Addr = "2001:db8::5".parse().unwrap();
        assert_eq!(pick_ipv6(&[ll, global]), Some(global));
        assert_eq!(pick_ipv6(&[ll]), Some(ll));
        assert_eq!(pick_ipv6(&[]), None);
    }

    #[test]
    fn formats_mac_like_ipconfig_did() {
        assert_eq!(
            format_mac(&[0x00, 0x15, 0x5d, 0x5b, 0x96, 0x1c]).as_deref(),
            Some("00:15:5D:5B:96:1C")
        );
        assert_eq!(format_mac(&[]), None);
        assert_eq!(format_mac(&[0; 6]), None);
    }

    #[test]
    fn wireless_only_from_known_media() {
        assert_eq!(wireless_from_if_type(IF_TYPE_IEEE80211), Some(true));
        assert_eq!(wireless_from_if_type(IF_TYPE_ETHERNET_CSMACD), Some(false));
        assert_eq!(wireless_from_if_type(53), None); // IF_TYPE_PROP_VIRTUAL
    }

    #[test]
    fn decodes_sockaddr_in_and_in6() {
        let mut sin = [0u8; 16];
        sin[..2].copy_from_slice(&AF_INET.to_ne_bytes());
        sin[2..4].copy_from_slice(&53u16.to_be_bytes()); // a port is ignored
        sin[4..8].copy_from_slice(&[192, 168, 2, 109]);
        assert_eq!(sockaddr_ip(&sin), Some(v4("192.168.2.109")));

        // The scope id (bytes 24..28) is not part of the address.
        let ll: Ipv6Addr = "fe80::1".parse().unwrap();
        let mut sin6 = [0u8; 28];
        sin6[..2].copy_from_slice(&AF_INET6.to_ne_bytes());
        sin6[8..24].copy_from_slice(&ll.octets());
        sin6[24..28].copy_from_slice(&12u32.to_ne_bytes());
        assert_eq!(sockaddr_ip(&sin6), Some(IpAddr::V6(ll)));
        assert_eq!(sockaddr_ip(&sin6).unwrap().to_string(), "fe80::1");
    }

    /// A short or foreign sockaddr is skipped, never read past its end.
    #[test]
    fn rejects_truncated_and_foreign_sockaddrs() {
        assert_eq!(sockaddr_ip(&[]), None);
        assert_eq!(sockaddr_ip(&[2]), None);
        let mut sin = [0u8; 16];
        sin[..2].copy_from_slice(&AF_INET.to_ne_bytes());
        assert_eq!(sockaddr_ip(&sin[..7]), None);
        let mut sin6 = [0u8; 28];
        sin6[..2].copy_from_slice(&AF_INET6.to_ne_bytes());
        assert_eq!(sockaddr_ip(&sin6[..23]), None);
        // Linux's AF_INET6 is 10; on Windows that is AF_IPX.
        let mut other = [0u8; 28];
        other[..2].copy_from_slice(&10u16.to_ne_bytes());
        assert_eq!(sockaddr_ip(&other), None);
    }

    #[test]
    fn interface_info_matches_what_ipconfig_listed() {
        let mut eth = adapter(1, "Ethernet");
        eth.mac = vec![0x00, 0x15, 0x5d, 0x5b, 0x96, 0x1c];
        eth.unicast = vec![v6("fe80::1"), v4("192.168.1.20"), v6("2001:db8::20")];
        let info = interface_info(&eth).unwrap();
        assert_eq!(info.name, "Ethernet");
        assert_eq!(info.ipv4.as_deref(), Some("192.168.1.20"));
        assert_eq!(info.ipv6.as_deref(), Some("2001:db8::20"));
        assert_eq!(info.mac.as_deref(), Some("00:15:5D:5B:96:1C"));
        assert_eq!(info.mtu, Some(1500));
        assert!(info.is_up);
        assert_eq!(info.is_wireless, Some(false));

        // Disconnected: no stale addresses, no MTU when the API has none.
        eth.is_up = false;
        eth.mtu = u32::MAX;
        let info = interface_info(&eth).unwrap();
        assert_eq!((info.ipv4, info.ipv6, info.mtu), (None, None, None));

        let mut lo = adapter(2, "Loopback Pseudo-Interface 1");
        lo.if_type = IF_TYPE_SOFTWARE_LOOPBACK;
        assert!(interface_info(&lo).is_none());
        assert!(interface_info(&adapter(3, "")).is_none());
    }

    #[test]
    fn guids_are_keyed_by_friendly_name() {
        let mut lo = adapter(2, "Loopback Pseudo-Interface 1");
        lo.if_type = IF_TYPE_SOFTWARE_LOOPBACK;
        let mut no_guid = adapter(3, "Teredo");
        no_guid.guid.clear();
        let guids = adapter_guids(&[
            adapter(1, "vEthernet (WSL)"),
            lo,
            no_guid,
            adapter(4, "vEthernet (WSL)"),
        ]);
        assert_eq!(guids.len(), 1);
        assert_eq!(
            guids["vEthernet (WSL)"],
            "{00000001-0000-0000-0000-000000000000}"
        );
    }

    /// The probe parses the server with `IpAddr::from_str`, so the text
    /// must carry no zone index, and Windows' placeholder fec0 servers must
    /// not be the one it picks.
    #[test]
    fn dns_server_text_drops_zone_and_site_local_placeholders() {
        assert_eq!(
            dns_server_text(v4("192.168.1.1")).as_deref(),
            Some("192.168.1.1")
        );
        assert_eq!(
            dns_server_text(v6("2001:4860:4860::8888")).as_deref(),
            Some("2001:4860:4860::8888")
        );
        let text = dns_server_text(v6("fe80::1")).unwrap();
        assert_eq!(text, "fe80::1");
        assert!(text.parse::<IpAddr>().is_ok());
        for placeholder in ["fec0:0:0:ffff::1", "fec0:0:0:ffff::2", "fec0:0:0:ffff::3"] {
            assert_eq!(dns_server_text(v6(placeholder)), None, "{placeholder}");
        }
        assert_eq!(dns_server_text(v4("0.0.0.0")), None);
    }

    #[test]
    fn dns_servers_put_the_default_route_adapter_first() {
        let mut lan = adapter(1, "Ethernet");
        lan.gateways = vec![v4("192.168.1.1")];
        lan.dns_servers = vec![v4("192.168.1.1"), v6("fec0:0:0:ffff::1")];
        let mut vpn = adapter(2, "WireGuard");
        vpn.dns_servers = vec![v4("10.8.0.1"), v4("192.168.1.1")];
        let mut host_only = adapter(3, "vEthernet (Default Switch)");
        host_only.dns_servers = vec![v4("172.20.0.1")];
        let mut down = adapter(4, "Wi-Fi");
        down.is_up = false;
        down.gateways = vec![v4("10.0.0.1")];
        down.dns_servers = vec![v4("10.0.0.1")];
        let adapters = [host_only, lan, vpn, down];

        // The VPN carries the default route: its resolver goes first, then
        // the LAN's (it has a gateway), then the host-only switch's. The
        // duplicate, the placeholder and the down adapter are dropped.
        assert_eq!(
            dns_servers(&adapters, Some(2)),
            ["10.8.0.1", "192.168.1.1", "172.20.0.1"]
        );
        // No default route known: adapters with a gateway first.
        assert_eq!(
            dns_servers(&adapters, None),
            ["192.168.1.1", "172.20.0.1", "10.8.0.1"]
        );
        assert!(dns_servers(&[], None).is_empty());
    }

    #[test]
    fn counters_map_to_interface_stats() {
        let c = IfCounters {
            in_octets: 1_000_000,
            in_ucast_pkts: 900,
            in_nucast_pkts: 100,
            in_discards: 3,
            in_errors: 2,
            out_octets: 500_000,
            out_ucast_pkts: 450,
            out_nucast_pkts: 50,
            out_discards: 5,
            out_errors: 4,
        };
        let s = interface_stats("Ethernet", &c);
        assert_eq!(s.name, "Ethernet");
        assert_eq!((s.rx_bytes, s.tx_bytes), (1_000_000, 500_000));
        assert_eq!((s.rx_packets, s.tx_packets), (1000, 500));
        assert_eq!((s.rx_errors, s.tx_errors), (2, 4));
        assert_eq!((s.rx_drops, s.tx_drops), (3, 5));
        assert_eq!((s.signal_dbm, s.tx_retries), (None, None));

        // A counter at the top of its range saturates rather than wrapping.
        let s = interface_stats(
            "x",
            &IfCounters {
                in_ucast_pkts: u64::MAX,
                in_nucast_pkts: 1,
                ..IfCounters::default()
            },
        );
        assert_eq!(s.rx_packets, u64::MAX);
    }

    #[test]
    fn stats_are_keyed_by_the_interface_list_names() {
        let mut lo = adapter(2, "Loopback Pseudo-Interface 1");
        lo.if_type = IF_TYPE_SOFTWARE_LOOPBACK;
        let adapters = [adapter(1, "Ethernet"), lo, adapter(3, "Wi-Fi")];
        let counters = HashMap::from([
            (
                1,
                IfCounters {
                    in_octets: 10,
                    ..IfCounters::default()
                },
            ),
            (
                2,
                IfCounters {
                    in_octets: 20,
                    ..IfCounters::default()
                },
            ),
            // A filter interface the adapter list does not name.
            (
                99,
                IfCounters {
                    in_octets: 30,
                    ..IfCounters::default()
                },
            ),
        ]);
        let stats = stats_by_name(&adapters, &counters);
        // Wi-Fi has no row and is left out rather than shown as zero.
        assert_eq!(stats.len(), 1);
        assert_eq!(stats["Ethernet"].rx_bytes, 10);
    }

    #[test]
    fn default_route_is_the_lowest_effective_metric() {
        let mut eth = adapter(1, "Ethernet");
        eth.ipv4_metric = 25;
        let mut wifi = adapter(2, "Wi-Fi");
        wifi.ipv4_metric = 50;
        let adapters = [eth, wifi];
        // Wi-Fi's route metric is the lower one (5 against 10), but with the
        // interface metrics added Ethernet wins, 35 against 55.
        let routes = [
            default_route(2, v4("10.0.0.1"), 5),
            default_route(1, v4("192.168.1.1"), 10),
        ];
        let best = default_routes(&routes, &adapters);
        assert_eq!(best[0].adapter.name, "Ethernet");
        assert_eq!(best[0].metric, 35);
        assert_eq!(default_gateway(&best).as_deref(), Some("192.168.1.1"));
    }

    #[test]
    fn non_default_and_down_routes_are_ignored() {
        let mut down = adapter(2, "Wi-Fi");
        down.is_up = false;
        let adapters = [adapter(1, "Ethernet"), down];
        let mut subnet = default_route(1, v4("0.0.0.0"), 1);
        subnet.destination = v4("192.168.1.0");
        subnet.prefix_len = 24;
        let routes = [
            subnet,
            default_route(2, v4("10.0.0.1"), 1),
            // A route on an interface the adapter list does not have.
            default_route(7, v4("172.16.0.1"), 1),
        ];
        assert!(default_routes(&routes, &adapters).is_empty());
        assert_eq!(default_gateway(&[]), None);
    }

    /// A full-tunnel VPN's on-link default carries the traffic, so it names
    /// the default interface, but the gateway is the LAN router behind it.
    #[test]
    fn on_link_default_names_the_interface_but_not_the_gateway() {
        let adapters = [adapter(1, "Ethernet"), adapter(2, "WireGuard")];
        let routes = [
            default_route(1, v4("192.168.1.1"), 35),
            default_route(2, v4("0.0.0.0"), 0),
        ];
        let best = default_routes(&routes, &adapters);
        assert_eq!(best[0].adapter.name, "WireGuard");
        assert_eq!(best[0].next_hop, None);
        assert_eq!(default_gateway(&best).as_deref(), Some("192.168.1.1"));
    }

    #[test]
    fn ipv6_default_decides_only_without_an_ipv4_one() {
        let mut eth = adapter(1, "Ethernet");
        eth.ipv4_metric = 50;
        let wifi = adapter(2, "Wi-Fi");
        let adapters = [eth, wifi];
        let routes = [
            default_route(2, v6("fe80::1"), 0),
            default_route(1, v4("192.168.1.1"), 0),
        ];
        let best = default_routes(&routes, &adapters);
        assert_eq!(best[0].adapter.name, "Ethernet");

        // IPv6 only: the interface comes from ::/0, but a link-local next
        // hop needs a zone the probes cannot parse, so there is no gateway.
        let v6_only = [default_route(2, v6("fe80::1"), 0)];
        let best = default_routes(&v6_only, &adapters);
        assert_eq!(best[0].adapter.name, "Wi-Fi");
        assert_eq!(default_gateway(&best), None);

        let routable = [default_route(2, v6("2001:db8::1"), 0)];
        let best = default_routes(&routable, &adapters);
        assert_eq!(default_gateway(&best).as_deref(), Some("2001:db8::1"));
    }
}
