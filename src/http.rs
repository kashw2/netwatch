//! The HTTP client shared by the remote publisher, the geo and whois
//! lookups and the Ollama insights call.
//!
//! ureq's default agent has no read or write timeout, so a server that
//! accepts the connection and then goes quiet holds the calling thread
//! forever. For the one geo or whois worker that means every later lookup
//! stalls behind it; for the remote sender it means the daemon's shutdown
//! drain never returns. Requests built from [`agent`] give up instead.
//!
//! Where ureq 3's defaults differ from what ureq 2 did here, [`build`] sets
//! the old behaviour by hand: no proxy from the environment, the same
//! redirect limit, and 4xx and 5xx statuses as errors.

use std::sync::OnceLock;
use std::time::Duration;

/// How long to wait for the connection to be established, the TLS handshake
/// included, and each of the handshake's reads and writes is bounded by
/// [`IO_TIMEOUT`] as well. Name resolution comes first and has no limit of
/// its own. ureq 2 could not interrupt the system resolver either.
pub const CONNECT_TIMEOUT: Duration = Duration::from_secs(5);

/// How long any single read or write may wait on the peer.
pub const IO_TIMEOUT: Duration = Duration::from_secs(10);

/// Redirects followed before the request fails with `TooManyRedirects`.
/// ureq 2's limit of 5 counted the response that broke it, so it followed
/// four; ureq 3 counts only the redirects it follows.
const MAX_REDIRECTS: u32 = 4;

/// The shared agent. Built once, so its connection pool is shared too.
pub fn agent() -> &'static ureq::Agent {
    static AGENT: OnceLock<ureq::Agent> = OnceLock::new();
    AGENT.get_or_init(|| build(CONNECT_TIMEOUT, IO_TIMEOUT))
}

/// GET `url` through the shared agent and read the body as text, up to
/// ureq's 10 MiB limit. A 4xx or 5xx answer is an error, the same as a
/// connection that fails.
pub fn get_text(url: &str) -> Result<String, ureq::Error> {
    agent().get(url).call()?.into_body().read_to_string()
}

fn build(connect: Duration, io: Duration) -> ureq::Agent {
    ureq::Agent::config_builder()
        .timeout_connect(Some(connect))
        .timeout_per_read(Some(io))
        .timeout_per_write(Some(io))
        // ureq 3 reads HTTP_PROXY, HTTPS_PROXY and ALL_PROXY by default;
        // ureq 2, built without its proxy-from-env feature, did not. Every
        // request here goes direct, as it always has.
        .proxy(None)
        .max_redirects(MAX_REDIRECTS)
        // Callers rely on this: the remote publisher classifies the status
        // carried by `Error::StatusCode`, and geo and whois treat any error
        // as no answer.
        .http_status_as_error(true)
        .build()
        .new_agent()
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::{Read, Write};
    use std::net::{TcpListener, TcpStream};
    use std::time::Instant;

    /// Answer `n` connections with `response`, one request each, and return
    /// how many requests arrived.
    fn serve(
        n: usize,
        response: impl Fn(u16) -> String + Send + 'static,
    ) -> (String, std::thread::JoinHandle<usize>) {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let port = listener.local_addr().unwrap().port();
        let handle = std::thread::spawn(move || {
            let mut seen = 0;
            for stream in listener.incoming().take(n) {
                let mut stream: TcpStream = stream.unwrap();
                read_head(&mut stream);
                seen += 1;
                let _ = stream.write_all(response(port).as_bytes());
            }
            seen
        });
        (format!("http://127.0.0.1:{port}/"), handle)
    }

    fn read_head(stream: &mut TcpStream) {
        let mut buf = Vec::new();
        let mut byte = [0u8; 1];
        while !buf.ends_with(b"\r\n\r\n") && stream.read(&mut byte).unwrap_or(0) == 1 {
            buf.push(byte[0]);
        }
    }

    /// A server that accepts and then never answers. Without a read timeout
    /// the request below would never return.
    #[test]
    fn a_silent_server_times_out_instead_of_hanging() {
        let listener = std::net::TcpListener::bind("127.0.0.1:0").unwrap();
        let url = format!("http://{}/", listener.local_addr().unwrap());
        let _silent = std::thread::spawn(move || {
            let held: Vec<_> = listener.incoming().take(1).collect();
            std::thread::sleep(Duration::from_secs(5));
            drop(held);
        });

        let started = Instant::now();
        let result = build(CONNECT_TIMEOUT, Duration::from_millis(200))
            .get(&url)
            .call();
        assert!(
            matches!(result, Err(ureq::Error::Timeout(ureq::Timeout::PerRead))),
            "{result:?}"
        );
        assert!(started.elapsed() < Duration::from_secs(3));
    }

    #[test]
    fn an_error_status_is_an_error_carrying_the_code() {
        let (url, server) = serve(1, |_| {
            "HTTP/1.1 503 Service Unavailable\r\nContent-Length: 0\r\nConnection: close\r\n\r\n"
                .into()
        });
        let result = get_text(&url);
        assert!(
            matches!(result, Err(ureq::Error::StatusCode(503))),
            "{result:?}"
        );
        assert_eq!(server.join().unwrap(), 1);
    }

    #[test]
    fn a_body_is_read_as_text() {
        let (url, server) = serve(1, |_| {
            "HTTP/1.1 200 OK\r\nContent-Length: 15\r\nConnection: close\r\n\r\n{\"status\":\"ok\"}"
                .into()
        });
        assert_eq!(get_text(&url).unwrap(), "{\"status\":\"ok\"}");
        server.join().unwrap();
    }

    /// The same limit ureq 2 had: four redirects followed, and the fifth
    /// redirect response is an error rather than a sixth request.
    #[test]
    fn redirects_stop_where_they_did_under_ureq_2() {
        let (url, server) = serve(5, |port| {
            format!(
                "HTTP/1.1 302 Found\r\nLocation: http://127.0.0.1:{port}/again\r\n\
                 Content-Length: 0\r\nConnection: close\r\n\r\n"
            )
        });
        let result = agent().get(&url).call();
        assert!(
            matches!(result, Err(ureq::Error::TooManyRedirects)),
            "{result:?}"
        );
        assert_eq!(server.join().unwrap(), 5);
    }

    /// ureq 3 would pick up a proxy from the environment by default. Checked
    /// on the configuration, since setting a proxy variable here would leak
    /// into every other test in the process.
    #[test]
    fn the_environment_proxy_is_not_used() {
        assert!(agent().config().proxy().is_none());
    }
}
