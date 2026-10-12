//! `attribution.rs` — per-query process attribution (CONTRACTS §8).
//!
//! CE resolves `dns_activity.process_id/process_name` at query time from the
//! Windows UDP owner table (client source port → PID,
//! `filter-enforcement.md` verdict a). The Linux equivalent implemented here:
//!
//! 1. an `inet_diag` (`SOCK_DIAG` netlink) query for the UDP socket bound to
//!    the client's source port on the listener's local address → socket
//!    inode;
//! 2. the inode → PID mapping via `/proc/<pid>/fd` symlinks;
//! 3. the PID → name mapping via `/proc/<pid>/comm`.
//!
//! A miss at any step degrades to the tolerated default
//! `process_id = 0 / process_name = "unknown"` (§8) — never a panic, never a
//! fatal error (CE treats a miss as fatal; that racy behavior is explicitly
//! *not* copied).

use std::collections::HashMap;
use std::net::IpAddr;
use std::path::Path;
use std::sync::Arc;

use crate::EngineMutex;

/// Tolerated attribution default (`process_id` column; §8).
pub const UNKNOWN_PROCESS_ID: i64 = 0;
/// Tolerated attribution default (`process_name` column; §8).
pub const UNKNOWN_PROCESS_NAME: &str = "unknown";

/// The attributed client identity of one query.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Attribution {
    /// Owner PID, or [`UNKNOWN_PROCESS_ID`].
    pub process_id: i64,
    /// Owner process name, or [`UNKNOWN_PROCESS_NAME`].
    pub process_name: String,
}

impl Default for Attribution {
    fn default() -> Self {
        Self {
            process_id: UNKNOWN_PROCESS_ID,
            process_name: UNKNOWN_PROCESS_NAME.to_string(),
        }
    }
}

/// The kernel/`proc` half of attribution, injectable for deterministic tests.
pub trait UdpOwnerLookup: Send + Sync {
    /// The `(pid, comm)` owning the UDP socket bound to `port` on `local`,
    /// if one can be found.
    fn owner_for_port(&self, port: u16, local: IpAddr) -> std::io::Result<Option<(i32, String)>>;
}

/// Production lookup: inet_diag netlink → `/proc/*/fd` → `/proc/<pid>/comm`,
/// with a small inode→owner cache (bounded, cleared on overflow) to keep the
/// per-query `/proc` scan off the hot path.
pub struct NetlinkProcDiag {
    cache: EngineMutex<HashMap<u32, (i32, String)>>,
}

/// Cache entries before the whole cache is dropped (inode reuse makes partial
/// eviction unsound; a full clear is the honest bounded choice).
const CACHE_CAPACITY: usize = 1024;

impl NetlinkProcDiag {
    /// Build the production lookup backend.
    pub fn new() -> Self {
        Self {
            cache: EngineMutex::new(HashMap::new()),
        }
    }
}

impl Default for NetlinkProcDiag {
    fn default() -> Self {
        Self::new()
    }
}

impl UdpOwnerLookup for NetlinkProcDiag {
    fn owner_for_port(&self, port: u16, local: IpAddr) -> std::io::Result<Option<(i32, String)>> {
        let Some(inode) = query_udp_socket_inode(port, local)? else {
            return Ok(None);
        };
        if let Some(hit) = self.cache.lock().get(&inode) {
            return Ok(Some(hit.clone()));
        }
        let Some(pid) = pid_for_inode(inode)? else {
            return Ok(None);
        };
        let comm = comm_for_pid(pid)?.unwrap_or_else(|| UNKNOWN_PROCESS_NAME.to_string());
        let mut cache = self.cache.lock();
        if cache.len() >= CACHE_CAPACITY {
            cache.clear();
        }
        cache.insert(inode, (pid, comm.clone()));
        Ok(Some((pid, comm)))
    }
}

/// Per-query attributor handed the client's UDP source port and the local
/// address the query arrived on.
pub struct ProcessAttributor {
    lookup: Arc<dyn UdpOwnerLookup>,
}

impl ProcessAttributor {
    /// Production attributor (inet_diag + `/proc`).
    pub fn new() -> Self {
        Self::with_lookup(Arc::new(NetlinkProcDiag::new()))
    }

    /// Attributor over an injected backend (tests, alternative transports).
    pub fn with_lookup(lookup: Arc<dyn UdpOwnerLookup>) -> Self {
        Self { lookup }
    }

    /// Attribute the query's client port; any miss/error yields
    /// [`Attribution::default`] (`unknown`/0, §8).
    pub fn attribute(&self, client_port: u16, local: IpAddr) -> Attribution {
        match self.lookup.owner_for_port(client_port, local) {
            Ok(Some((pid, name))) if pid > 0 && !name.is_empty() => Attribution {
                process_id: pid as i64,
                process_name: name,
            },
            Ok(_) => Attribution::default(),
            Err(_) => Attribution::default(),
        }
    }
}

impl Default for ProcessAttributor {
    fn default() -> Self {
        Self::new()
    }
}

// --- inet_diag (SOCK_DIAG) netlink -----------------------------------------
//
// Hand-rolled over raw netlink syscalls: the request is an
// `inet_diag_req_v2` dump for `IPPROTO_UDP` filtered on the local port; each
// reply is an `inet_diag_msg` from which the socket inode is extracted.

const NETLINK_SOCK_DIAG: libc::c_int = 4;
const SOCK_DIAG_BY_FAMILY: u16 = 20;
const NLMSG_ERROR: u16 = 2;
const NLMSG_DONE: u16 = 3;
/// `NLM_F_REQUEST | NLM_F_DUMP`.
const NLM_F_REQUEST_DUMP: u16 = 0x01 | 0x300;
/// `sizeof(struct inet_diag_msg)`.
const INET_DIAG_MSG_LEN: usize = 72;
/// Offset of `idiag_inode` inside `struct inet_diag_msg`.
const INODE_OFFSET: usize = 68;
/// Kernel netlink I/O timeout so a wedged netlink can never hang a query.
const NETLINK_IO_TIMEOUT: libc::timeval = libc::timeval {
    tv_sec: 2,
    tv_usec: 0,
};

struct FdGuard(libc::c_int);

impl Drop for FdGuard {
    fn drop(&mut self) {
        unsafe { libc::close(self.0) };
    }
}

/// Serializes one `SOCK_DIAG_BY_FAMILY` dump request for the UDP socket bound
/// to `port` on `local`.
pub(crate) fn build_inet_diag_request(port: u16, local: IpAddr) -> Vec<u8> {
    let family: u8 = if local.is_ipv4() {
        libc::AF_INET as u8
    } else {
        libc::AF_INET6 as u8
    };
    // struct inet_diag_sockid: sport(2) dport(2) src(16) dst(16) if(4) cookie(8).
    let mut sockid = [0u8; 48];
    sockid[0..2].copy_from_slice(&port.to_be_bytes());
    match local {
        IpAddr::V4(a) => sockid[4..8].copy_from_slice(&a.octets()),
        IpAddr::V6(a) => sockid[4..20].copy_from_slice(&a.octets()),
    }
    sockid[40..48].fill(0xFF); // cookie = INET_DIAG_NOCOOKIE

    // struct inet_diag_req_v2: family, protocol, ext, pad, states, sockid.
    let mut body = Vec::with_capacity(56);
    body.push(family);
    body.push(libc::IPPROTO_UDP as u8);
    body.push(0);
    body.push(0);
    body.extend_from_slice(&u32::MAX.to_le_bytes()); // idiag_states: all
    body.extend_from_slice(&sockid);

    let total = 16 + body.len();
    let mut message = Vec::with_capacity(total);
    message.extend_from_slice(&(total as u32).to_le_bytes()); // nlmsg_len
    message.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_le_bytes()); // nlmsg_type
    message.extend_from_slice(&NLM_F_REQUEST_DUMP.to_le_bytes()); // nlmsg_flags
    message.extend_from_slice(&1u32.to_le_bytes()); // nlmsg_seq
    message.extend_from_slice(&0u32.to_le_bytes()); // nlmsg_pid
    message.extend_from_slice(&body);
    message
}

/// Scans a netlink reply buffer (possibly multi-message dump) for the
/// `inet_diag_msg` matching `port`/`local`; returns its `idiag_inode`.
pub(crate) fn find_udp_inode(payload: &[u8], port: u16, local: IpAddr) -> Option<u32> {
    let mut offset = 0usize;
    while offset + 16 <= payload.len() {
        let len = u32::from_le_bytes(payload[offset..offset + 4].try_into().ok()?) as usize;
        let msg_type = u16::from_le_bytes(payload[offset + 4..offset + 6].try_into().ok()?);
        if len < 16 || offset + len > payload.len() {
            break;
        }
        match msg_type {
            SOCK_DIAG_BY_FAMILY => {
                if let Some(inode) =
                    parse_inet_diag_msg(&payload[offset + 16..offset + len], port, local)
                {
                    return Some(inode);
                }
            }
            NLMSG_DONE | NLMSG_ERROR => return None,
            _ => {}
        }
        offset += (len + 3) & !3; // NLMSG_ALIGN
    }
    None
}

/// Parses one `inet_diag_msg`, matching the local port and local address.
pub(crate) fn parse_inet_diag_msg(data: &[u8], port: u16, local: IpAddr) -> Option<u32> {
    if data.len() < INET_DIAG_MSG_LEN {
        return None;
    }
    let family = data[0];
    let sport = u16::from_be_bytes([data[4], data[5]]);
    if sport != port {
        return None;
    }
    let address_matches = match local {
        IpAddr::V4(a) => family == libc::AF_INET as u8 && data[8..12] == a.octets(),
        IpAddr::V6(a) => family == libc::AF_INET6 as u8 && data[8..24] == a.octets(),
    };
    if !address_matches {
        return None;
    }
    Some(u32::from_le_bytes([
        data[INODE_OFFSET],
        data[INODE_OFFSET + 1],
        data[INODE_OFFSET + 2],
        data[INODE_OFFSET + 3],
    ]))
}

/// Asks the kernel for the inode of the UDP socket bound to `port` on `local`.
fn query_udp_socket_inode(port: u16, local: IpAddr) -> std::io::Result<Option<u32>> {
    let request = build_inet_diag_request(port, local);
    let fd = unsafe {
        libc::socket(
            libc::AF_NETLINK,
            libc::SOCK_DGRAM | libc::SOCK_CLOEXEC,
            NETLINK_SOCK_DIAG,
        )
    };
    if fd < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let _guard = FdGuard(fd);
    unsafe {
        libc::setsockopt(
            fd,
            libc::SOL_SOCKET,
            libc::SO_RCVTIMEO,
            &NETLINK_IO_TIMEOUT as *const libc::timeval as *const libc::c_void,
            std::mem::size_of::<libc::timeval>() as libc::socklen_t,
        );
    }
    // libc 0.2.190 exposes `nl_pad` privately (padding); zero-initialize and
    // set only the public family field.
    let mut kernel_addr: libc::sockaddr_nl = unsafe { std::mem::zeroed() };
    kernel_addr.nl_family = libc::AF_NETLINK as libc::sa_family_t;
    let sent = unsafe {
        libc::sendto(
            fd,
            request.as_ptr() as *const libc::c_void,
            request.len(),
            0,
            &kernel_addr as *const libc::sockaddr_nl as *const libc::sockaddr,
            std::mem::size_of::<libc::sockaddr_nl>() as libc::socklen_t,
        )
    };
    if sent < 0 {
        return Err(std::io::Error::last_os_error());
    }
    let mut buffer = [0u8; 8192];
    loop {
        let received = unsafe {
            libc::recv(
                fd,
                buffer.as_mut_ptr() as *mut libc::c_void,
                buffer.len(),
                0,
            )
        };
        if received < 0 {
            return Err(std::io::Error::last_os_error());
        }
        if received == 0 {
            return Ok(None);
        }
        if let Some(inode) = find_udp_inode(&buffer[..received as usize], port, local) {
            return Ok(Some(inode));
        }
    }
}

/// Maps a socket inode to its owning PID via `/proc/<pid>/fd` symlinks.
fn pid_for_inode(inode: u32) -> std::io::Result<Option<i32>> {
    let expected = format!("socket:[{inode}]");
    let proc = std::fs::read_dir("/proc")?;
    for entry in proc.flatten() {
        let pid: i32 = match entry.file_name().to_str().and_then(|s| s.parse().ok()) {
            Some(pid) => pid,
            None => continue,
        };
        let fds = match std::fs::read_dir(entry.path().join("fd")) {
            Ok(fds) => fds,
            Err(_) => continue, // process exited or not ours; keep scanning
        };
        for fd in fds.flatten() {
            match std::fs::read_link(fd.path()) {
                Ok(target) if fd_target_is_socket(&target, &expected) => {
                    return Ok(Some(pid));
                }
                _ => {}
            }
        }
    }
    Ok(None)
}

fn fd_target_is_socket(target: &Path, expected: &str) -> bool {
    target.to_str() == Some(expected)
}

/// Reads `/proc/<pid>/comm` (trailing newline trimmed).
fn comm_for_pid(pid: i32) -> std::io::Result<Option<String>> {
    match std::fs::read_to_string(format!("/proc/{pid}/comm")) {
        Ok(text) => {
            let name = text.trim();
            if name.is_empty() {
                Ok(None)
            } else {
                Ok(Some(name.to_string()))
            }
        }
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// Serializes a netlink reply payload containing one `inet_diag_msg`.
    fn inet_diag_reply(sport: u16, local: IpAddr, inode: u32) -> Vec<u8> {
        let mut msg = vec![0u8; INET_DIAG_MSG_LEN];
        msg[0] = if local.is_ipv4() {
            libc::AF_INET as u8
        } else {
            libc::AF_INET6 as u8
        };
        msg[4..6].copy_from_slice(&sport.to_be_bytes());
        match local {
            IpAddr::V4(a) => msg[8..12].copy_from_slice(&a.octets()),
            IpAddr::V6(a) => msg[8..24].copy_from_slice(&a.octets()),
        }
        msg[INODE_OFFSET..INODE_OFFSET + 4].copy_from_slice(&inode.to_le_bytes());

        let total = 16 + msg.len();
        let mut payload = Vec::with_capacity(total);
        payload.extend_from_slice(&(total as u32).to_le_bytes());
        payload.extend_from_slice(&SOCK_DIAG_BY_FAMILY.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload.extend_from_slice(&msg);
        payload
    }

    fn nlmsg_of(msg_type: u16) -> Vec<u8> {
        let mut payload = Vec::with_capacity(16);
        payload.extend_from_slice(&16u32.to_le_bytes());
        payload.extend_from_slice(&msg_type.to_le_bytes());
        payload.extend_from_slice(&0u16.to_le_bytes());
        payload.extend_from_slice(&0u32.to_le_bytes());
        payload.extend_from_slice(&0u32.to_be_bytes());
        payload
    }

    #[test]
    fn request_wire_shape() {
        let v4 = build_inet_diag_request(0xC001, "127.0.0.2".parse().unwrap());
        assert_eq!(v4.len(), 16 + 56);
        assert_eq!(
            u32::from_le_bytes(v4[0..4].try_into().unwrap()) as usize,
            v4.len()
        );
        assert_eq!(
            u16::from_le_bytes(v4[4..6].try_into().unwrap()),
            SOCK_DIAG_BY_FAMILY
        );
        assert_eq!(
            u16::from_le_bytes(v4[6..8].try_into().unwrap()),
            NLM_F_REQUEST_DUMP
        );
        assert_eq!(v4[16], libc::AF_INET as u8);
        assert_eq!(v4[17], libc::IPPROTO_UDP as u8);
        // idiag_states (all states, LE) between the fixed prefix and the sockid.
        assert_eq!(u32::from_le_bytes(v4[20..24].try_into().unwrap()), u32::MAX);
        // sport (BE) opens the sockid at body offset 8 = message offset 24.
        assert_eq!(u16::from_be_bytes(v4[24..26].try_into().unwrap()), 0xC001);
        // src = 127.0.0.2 (network order) at message offset 28.
        assert_eq!(&v4[28..32], &[127, 0, 0, 2]);
        // cookie = INET_DIAG_NOCOOKIE at sockid offset 40 (message offset 64).
        assert_eq!(&v4[64..72], &[0xFF; 8]);

        let v6 = build_inet_diag_request(53, "::1".parse().unwrap());
        assert_eq!(v6[16], libc::AF_INET6 as u8);
        assert_eq!(v6[28 + 15], 1, "::1 last byte");
    }

    #[test]
    fn reply_parser_matches_port_and_address() {
        let local: IpAddr = "127.0.0.2".parse().unwrap();
        let payload = inet_diag_reply(42424, local, 987654);
        assert_eq!(find_udp_inode(&payload, 42424, local), Some(987654));
        // Wrong port / wrong address / trailing garbage → no match.
        assert_eq!(find_udp_inode(&payload, 42425, local), None);
        let other: IpAddr = "127.0.0.3".parse().unwrap();
        assert_eq!(find_udp_inode(&payload, 42424, other), None);
        assert_eq!(find_udp_inode(&payload[..10], 42424, local), None);
        assert_eq!(find_udp_inode(&[], 42424, local), None);
    }

    #[test]
    fn reply_parser_walks_dump_frames() {
        let local: IpAddr = "::1".parse().unwrap();
        let mut frames = Vec::new();
        frames.extend_from_slice(&inet_diag_reply(1, local, 111));
        frames.extend_from_slice(&inet_diag_reply(2, local, 222));
        frames.extend_from_slice(&nlmsg_of(NLMSG_DONE));
        assert_eq!(find_udp_inode(&frames, 2, local), Some(222));
        assert_eq!(find_udp_inode(&frames, 3, local), None);

        // NLMSG_ERROR terminates the walk without a match.
        let mut error_walk = Vec::new();
        error_walk.extend_from_slice(&nlmsg_of(NLMSG_ERROR));
        error_walk.extend_from_slice(&inet_diag_reply(5, local, 333));
        assert_eq!(find_udp_inode(&error_walk, 5, local), None);
    }

    #[test]
    fn v6_reply_does_not_match_v4_address() {
        let mut payload = inet_diag_reply(9, "::1".parse().unwrap(), 42);
        payload[0] = libc::AF_INET6 as u8;
        let local: IpAddr = "127.0.0.2".parse().unwrap();
        assert_eq!(find_udp_inode(&payload, 9, local), None);
    }

    enum Ownership {
        Found(i32, String),
        Missing,
        Denied,
    }

    struct FakeLookup {
        ownership: EngineMutex<Ownership>,
    }

    impl UdpOwnerLookup for FakeLookup {
        fn owner_for_port(
            &self,
            _port: u16,
            _local: IpAddr,
        ) -> std::io::Result<Option<(i32, String)>> {
            match &*self.ownership.lock() {
                Ownership::Found(pid, name) => Ok(Some((*pid, name.clone()))),
                Ownership::Missing => Ok(None),
                Ownership::Denied => Err(std::io::Error::new(
                    std::io::ErrorKind::PermissionDenied,
                    "netlink denied",
                )),
            }
        }
    }

    fn fake(ownership: Ownership) -> ProcessAttributor {
        ProcessAttributor::with_lookup(Arc::new(FakeLookup {
            ownership: EngineMutex::new(ownership),
        }))
    }

    #[test]
    fn attribution_resolves_owner_when_kernel_answers() {
        let attributor = fake(Ownership::Found(4242, "firefox".to_string()));
        let got = attributor.attribute(42424, "127.0.0.2".parse().unwrap());
        assert_eq!(got.process_id, 4242);
        assert_eq!(got.process_name, "firefox");
    }

    /// The tolerated default: no owner found → unknown/0, no panic (§8).
    #[test]
    fn attribution_gracefully_degrades_to_unknown() {
        let local: IpAddr = "127.0.0.2".parse().unwrap();
        assert_eq!(
            fake(Ownership::Missing).attribute(1, local),
            Attribution::default()
        );
        assert_eq!(
            fake(Ownership::Denied).attribute(1, local),
            Attribution::default()
        );
        // Nonsense owners are also normalized to the default.
        assert_eq!(
            fake(Ownership::Found(0, "x".to_string())).attribute(1, local),
            Attribution::default()
        );
        assert_eq!(
            fake(Ownership::Found(7, String::new())).attribute(1, local),
            Attribution::default()
        );
        assert_eq!(Attribution::default().process_id, UNKNOWN_PROCESS_ID);
        assert_eq!(Attribution::default().process_name, UNKNOWN_PROCESS_NAME);
    }
}
