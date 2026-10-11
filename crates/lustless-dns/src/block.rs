//! `block.rs` — block-answer synthesis and the loopback block page (§8).
//!
//! Synthesis follows CE's `overrideForBlocking` mechanics
//! (`filter-enforcement.md` verdict b): parse the question of the upstream
//! reply (or the client query), zero the answer/authority/additional sections,
//! clear the RCODE to NOERROR, and append synthesized records — A `127.0.0.2`
//! / AAAA `::1` plus a CNAME to `blocked.lustless.local` — so the daemon's
//! loopback HTTP block page (CONTRACTS §8 "The `blocked.lustless.local`
//! vhost serves a static block page over `127.0.0.2:80`") is reachable.

use std::net::{Ipv4Addr, Ipv6Addr};
use std::sync::Arc;

use hickory_proto::op::{Message, MessageType, OpCode, ResponseCode};
use hickory_proto::rr::rdata::{A, AAAA, CNAME};
use hickory_proto::rr::{Name, RData, Record, RecordType};
use hickory_proto::ProtoError;
use thiserror::Error;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio::net::{TcpListener, TcpStream};
use tracing::debug;

/// Default synthetic CNAME target of block answers (§8; CE's analogue was
/// `blocked.cvnt.net`).
pub const DEFAULT_BLOCK_HOST: &str = "blocked.lustless.local";

/// Address records of synthesized block answers (§8).
pub const BLOCK_ANSWER_IPV4: Ipv4Addr = Ipv4Addr::new(127, 0, 0, 2);
/// Address record AAAA of synthesized block answers (§8).
pub const BLOCK_ANSWER_IPV6: Ipv6Addr = Ipv6Addr::LOCALHOST;

/// TTL of synthesized records.
pub const BLOCK_TTL: u32 = 60;

/// Bound on a single HTTP request head read by the block page server.
const MAX_REQUEST_HEAD: usize = 8 * 1024;
/// Idle timeout for one block-page HTTP exchange.
const CLIENT_IO_TIMEOUT: std::time::Duration = std::time::Duration::from_secs(5);

/// Why block synthesis refused to produce an answer.
#[derive(Debug, Error)]
pub enum BlockError {
    /// The upstream reply/client query could not be parsed as DNS wire.
    #[error("unparseable dns message: {0}")]
    Unparseable(String),
    /// The message had no question section to echo.
    #[error("message has no question section")]
    NoQuestion,
    /// The synthesized answer failed to serialize (cannot happen for the
    /// fixed record set; kept so callers degrade to SERVFAIL, never panic).
    #[error("codec error: {0}")]
    Proto(#[from] ProtoError),
}

/// Synthesize the §8 block answer for `upstream` (the wire bytes of the
/// upstream reply, or — when both paths are dead — the client query).
///
/// The question section, transaction ID and RD flag of `upstream` are
/// preserved; ANCOUNT/NSCOUNT/ARCOUNT are zeroed and the following records are
/// appended to the answer section:
///
/// * a CNAME to `block_host` (always),
/// * an A `127.0.0.2` record for A queries (§8),
/// * an AAAA `::1` record for AAAA queries (§8).
///
/// Other query types receive the CNAME alone, which makes the stub resolver
/// chase into a follow-up A/AAAA query that is blocked in turn.
pub fn synthesize_block_answer(upstream: &[u8], block_host: &Name) -> Result<Vec<u8>, BlockError> {
    let upstream = Message::from_vec(upstream)
        .map_err(|e| BlockError::Unparseable(e.to_string()))?;
    let Some(question) = upstream.queries().first() else {
        return Err(BlockError::NoQuestion);
    };

    let mut out = Message::new();
    out.set_id(upstream.id());
    out.set_message_type(MessageType::Response);
    out.set_op_code(OpCode::Query);
    out.set_recursion_desired(upstream.recursion_desired());
    out.set_response_code(ResponseCode::NoError);
    out.add_query(question.clone());

    out.add_answer(Record::from_rdata(
        block_host.clone(),
        BLOCK_TTL,
        RData::CNAME(CNAME(block_host.clone())),
    ));
    match question.query_type() {
        RecordType::A => {
            out.add_answer(Record::from_rdata(
                block_host.clone(),
                BLOCK_TTL,
                RData::A(A(BLOCK_ANSWER_IPV4)),
            ));
        }
        RecordType::AAAA => {
            out.add_answer(Record::from_rdata(
                block_host.clone(),
                BLOCK_TTL,
                RData::AAAA(AAAA(BLOCK_ANSWER_IPV6)),
            ));
        }
        _ => {}
    }
    Ok(out.to_vec()?)
}

/// The static HTML block page served over `127.0.0.2:80` (§8).
pub fn default_block_page_html(block_host: &str) -> String {
    format!(
        "<!DOCTYPE html>\n\
<html lang=\"en\">\n\
<head>\n\
<meta charset=\"utf-8\">\n\
<meta name=\"viewport\" content=\"width=device-width, initial-scale=1\">\n\
<title>Site blocked</title>\n\
<style>\n\
body {{ font-family: system-ui, sans-serif; margin: 0; display: grid; place-items: center;\n\
       min-height: 100vh; background: #f4f4f6; color: #1c1c1e; }}\n\
main {{ max-width: 32rem; padding: 2rem; text-align: center; }}\n\
h1 {{ font-size: 1.6rem; }}\n\
p {{ line-height: 1.5; color: #3a3a3c; }}\n\
footer {{ margin-top: 2rem; font-size: .85rem; color: #8e8e93; }}\n\
</style>\n\
</head>\n\
<body>\n\
<main>\n\
<h1>This site is blocked</h1>\n\
<p>LustLess filtering blocked this page. If you think this is a mistake,\n\
contact the account holder or your system administrator.</p>\n\
</main>\n\
<footer>Served by LustLess &middot; {0}</footer>\n\
</body>\n\
</html>\n",
        block_host
    )
}

/// Loopback HTTP server for the §8 block page: any vhost resolving to the
/// synthesized block addresses (`blocked.lustless.local` via CNAME, or the
/// originally requested domain) receives the static page.
///
/// The daemon starts it when `dns.block_page = true`:
/// `BlockPageServer::bind("127.0.0.2:80".parse()?, host)?.run().await`.
pub struct BlockPageServer {
    listener: TcpListener,
    html: Arc<str>,
}

impl BlockPageServer {
    /// Bind the block page listener (requires the daemon's root privileges for
    /// port 80; the daemon owns bind failures).
    pub async fn bind(addr: std::net::SocketAddr, block_host: &str) -> std::io::Result<Self> {
        let listener = TcpListener::bind(addr).await?;
        Ok(Self { listener, html: Arc::from(default_block_page_html(block_host)) })
    }

    /// The actual bound address (useful when binding port 0 in tests).
    pub fn local_addr(&self) -> std::io::Result<std::net::SocketAddr> {
        self.listener.local_addr()
    }

    /// Accept loop: one task per connection; malformed or slow requests are
    /// closed without a response and never panic.
    pub async fn run(self) -> std::io::Result<()> {
        loop {
            let (stream, peer) = self.listener.accept().await?;
            let html = Arc::clone(&self.html);
            tokio::spawn(async move {
                if let Err(e) = serve_connection(stream, &html).await {
                    debug!(%peer, error = %e, "block page connection failed");
                }
            });
        }
    }
}

async fn serve_connection(mut stream: TcpStream, html: &str) -> std::io::Result<()> {
    let mut head = Vec::with_capacity(256);
    let mut chunk = [0u8; 512];
    loop {
        let n = tokio::time::timeout(CLIENT_IO_TIMEOUT, stream.read(&mut chunk))
            .await
            .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "request head timeout"))??;
        if n == 0 {
            break;
        }
        head.extend_from_slice(&chunk[..n]);
        if head.windows(4).any(|w| w == b"\r\n\r\n") || head.len() >= MAX_REQUEST_HEAD {
            break;
        }
    }
    if head.is_empty() {
        return Ok(());
    }
    let head = String::from_utf8_lossy(&head);
    let method = head.split_whitespace().next().unwrap_or("");
    let (status, body) = match method {
        "GET" | "HEAD" => ("200 OK", html),
        _ => ("405 Method Not Allowed", "method not allowed\n"),
    };
    let response_head = format!(
        "HTTP/1.1 {status}\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nCache-Control: no-store\r\nConnection: close\r\n\r\n",
        body.len()
    );
    let mut response = response_head.into_bytes();
    if method != "HEAD" {
        response.extend_from_slice(body.as_bytes());
    }
    tokio::time::timeout(CLIENT_IO_TIMEOUT, stream.write_all(&response))
        .await
        .map_err(|_| std::io::Error::new(std::io::ErrorKind::TimedOut, "response timeout"))??;
    stream.flush().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::Query;
    use hickory_proto::rr::rdata::SOA;

    fn test_host() -> Name {
        Name::from_ascii(DEFAULT_BLOCK_HOST).unwrap()
    }

    /// A realistic upstream reply: question + a real A answer + authority +
    /// additional sections — all of which synthesis MUST zero (§8).
    fn upstream_reply(qtype: RecordType) -> Vec<u8> {
        let mut msg = Message::new();
        msg.set_id(0x1337);
        msg.set_message_type(MessageType::Response);
        msg.set_op_code(OpCode::Query);
        msg.set_recursion_desired(true);
        msg.set_authoritative(true);
        msg.set_response_code(ResponseCode::NXDomain);
        msg.add_query(Query::query(Name::from_ascii("bad.example.com").unwrap(), qtype));
        msg.add_answer(Record::from_rdata(
            Name::from_ascii("bad.example.com").unwrap(),
            300,
            RData::A(A(Ipv4Addr::new(203, 0, 113, 7))),
        ));
        msg.add_name_server(Record::from_rdata(
            Name::from_ascii("example.com").unwrap(),
            300,
            RData::SOA(SOA::new(
                Name::from_ascii("ns1.example.com").unwrap(),
                Name::from_ascii("hostmaster.example.com").unwrap(),
                1,
                3600,
                600,
                86400,
                300,
            )),
        ));
        msg.add_additional(Record::from_rdata(
            Name::from_ascii("ns1.example.com").unwrap(),
            300,
            RData::A(A(Ipv4Addr::new(198, 51, 100, 1))),
        ));
        msg.to_vec().unwrap()
    }

    #[test]
    fn a_query_synthesis_is_byte_level_correct() {
        let upstream = upstream_reply(RecordType::A);
        let wire = synthesize_block_answer(&upstream, &test_host()).unwrap();

        // Header: ID preserved, QR set, RCODE cleared to NOERROR, and the
        // answer/authority/additional counts zeroed except the two
        // synthesized answers (§8 byte-level shape).
        assert_eq!(u16::from_be_bytes([wire[0], wire[1]]), 0x1337);
        let flags = u16::from_be_bytes([wire[2], wire[3]]);
        assert_ne!(flags & 0x8000, 0, "QR must be set");
        assert_eq!(flags & 0x000F, 0, "RCODE must be NOERROR");
        assert_eq!(u16::from_be_bytes([wire[4], wire[5]]), 1, "QDCOUNT preserved");
        assert_eq!(u16::from_be_bytes([wire[6], wire[7]]), 2, "ANCOUNT = CNAME + A");
        assert_eq!(u16::from_be_bytes([wire[8], wire[9]]), 0, "NSCOUNT zeroed");
        assert_eq!(u16::from_be_bytes([wire[10], wire[11]]), 0, "ARCOUNT zeroed");

        let parsed = Message::from_vec(&wire).unwrap();
        assert_eq!(parsed.id(), 0x1337);
        assert_eq!(parsed.response_code(), ResponseCode::NoError);
        assert_eq!(parsed.queries().len(), 1);
        assert_eq!(parsed.queries()[0].name().to_utf8(), "bad.example.com.");
        assert_eq!(parsed.queries()[0].query_type(), RecordType::A);
        assert!(parsed.name_servers().is_empty());
        assert!(parsed.additionals().is_empty());

        assert_eq!(parsed.answers().len(), 2);
        match parsed.answers()[0].data() {
            RData::CNAME(c) => assert_eq!(c.0.to_utf8(), format!("{DEFAULT_BLOCK_HOST}.")),
            other => panic!("first answer must be the synthetic CNAME, got {other:?}"),
        }
        match parsed.answers()[1].data() {
            RData::A(a) => assert_eq!(a.0, BLOCK_ANSWER_IPV4),
            other => panic!("second answer must be the synthetic A, got {other:?}"),
        }
        // The upstream answer (203.0.113.7) is gone.
        let rendered = format!("{parsed:?}");
        assert!(!rendered.contains("203.0.113.7"));
    }

    #[test]
    fn aaaa_query_synthesizes_loopback_aaaa() {
        let wire = synthesize_block_answer(&upstream_reply(RecordType::AAAA), &test_host()).unwrap();
        let parsed = Message::from_vec(&wire).unwrap();
        assert_eq!(parsed.answers().len(), 2);
        match parsed.answers()[1].data() {
            RData::AAAA(aaaa) => assert_eq!(aaaa.0, BLOCK_ANSWER_IPV6),
            other => panic!("expected synthetic AAAA, got {other:?}"),
        }
    }

    #[test]
    fn other_qtypes_get_cname_only() {
        let wire = synthesize_block_answer(&upstream_reply(RecordType::MX), &test_host()).unwrap();
        let parsed = Message::from_vec(&wire).unwrap();
        assert_eq!(parsed.answers().len(), 1);
        assert!(matches!(parsed.answers()[0].data(), RData::CNAME(_)));
        assert_eq!(u16::from_be_bytes([wire[6], wire[7]]), 1);
    }

    #[test]
    fn custom_block_host_is_used_verbatim() {
        let host = Name::from_ascii("blocked.example.test").unwrap();
        let wire = synthesize_block_answer(&upstream_reply(RecordType::A), &host).unwrap();
        let parsed = Message::from_vec(&wire).unwrap();
        match parsed.answers()[0].data() {
            RData::CNAME(c) => assert_eq!(c.0.to_utf8(), "blocked.example.test."),
            other => panic!("expected CNAME, got {other:?}"),
        }
    }

    #[test]
    fn unparseable_or_questionless_input_errors_without_panicking() {
        assert!(matches!(
            synthesize_block_answer(&[0x00, 0x01, 0x02], &test_host()),
            Err(BlockError::Unparseable(_))
        ));
        // Valid message but no question section.
        let mut empty = Message::new();
        empty.set_id(7);
        empty.set_message_type(MessageType::Response);
        let wire = empty.to_vec().unwrap();
        assert!(matches!(
            synthesize_block_answer(&wire, &test_host()),
            Err(BlockError::NoQuestion)
        ));
    }

    #[test]
    fn default_block_page_is_static_html_with_host() {
        let html = default_block_page_html(DEFAULT_BLOCK_HOST);
        assert!(html.starts_with("<!DOCTYPE html>"));
        assert!(html.contains("This site is blocked"));
        assert!(html.contains(DEFAULT_BLOCK_HOST));
        assert!(html.ends_with("</html>\n"));
    }
}
