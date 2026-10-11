//! `verdicts.rs` — the per-query verdict engine (CONTRACTS §8).
//!
//! Implements the §8 decision tree over CE's 15 `resolution_type` codes,
//! kept **byte-exact** (table verbatim from `filter-enforcement.md` verdict b;
//! the numeric codes are CE's `FUN_1402b9a10` mapper values). The engine is a
//! pure function of its inputs — no I/O, no clock, no randomness — so timeout
//! classification is jitter-free and exhaustively unit-testable (§16).

use hickory_proto::op::Message;
use hickory_proto::rr::{Name, RData};

/// RPZ block marker CE looks for in upstream filter answers (§8
/// `BlockedFilter` trigger; literal `cleanbrowsing.rpz.noc.org`).
pub const RPZ_BLOCK_MARKER: &str = "cleanbrowsing.rpz.noc.org";

/// Tri-state domain-override verdict (CE `custom_domain_overrides` /
/// `global_domain_overrides` semantics: 0=allow, 1=block, 2=n/a —
/// `filter-enforcement.md` §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum OverrideVerdict {
    /// Explicit allow (CE tri-state 0).
    Allow,
    /// Explicit block (CE tri-state 1).
    Block,
    /// No override matches (CE tri-state 2, the initialized default).
    NotApplicable,
}

impl OverrideVerdict {
    /// Maps CE's numeric tri-state (0/1/anything-else) to the enum.
    pub fn from_tristate(value: u8) -> Self {
        match value {
            0 => OverrideVerdict::Allow,
            1 => OverrideVerdict::Block,
            _ => OverrideVerdict::NotApplicable,
        }
    }
}

/// Outcome of one of the two parallel resolution paths (§8 "Dual resolution").
#[derive(Debug, Clone, PartialEq, Eq)]
pub enum PathOutcome {
    /// A well-formed DNS response wire message was received.
    Answer(Vec<u8>),
    /// The path exceeded its per-lookup timeout.
    Timeout,
    /// Transport failure or an unusable (unparseable) response.
    Failure,
}

impl PathOutcome {
    /// The wire answer bytes, when the path produced one.
    pub fn answer_bytes(&self) -> Option<&[u8]> {
        match self {
            PathOutcome::Answer(bytes) => Some(bytes),
            _ => None,
        }
    }
}

/// Which path's answer the client is served (CE `local_2a7` response-endpoint
/// selector, `filter-enforcement.md` mechanism §1.4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ResponseEndpoint {
    /// The DoH/filter answer.
    Filter,
    /// The user-resolver answer.
    User,
    /// A locally synthesized answer (block synthesis or error response).
    Local,
}

/// CE's 15 `resolution_type` verdict codes (CONTRACTS §8 table, verbatim).
#[derive(Debug, Clone, Copy, PartialEq, Eq, Hash)]
pub enum VerdictType {
    /// Custom-override block (code 0xb).
    BlockedCustom,
    /// Global-override block (code 10).
    BlockedGlobal,
    /// Upstream filter block — RPZ marker in the filter answer (code 9).
    BlockedFilter,
    /// Explicit custom allow override (code 5).
    UnrestrictedAllowCustom,
    /// Explicit global allow override (code 4).
    UnrestrictedAllowGlobal,
    /// Clean filter answer (code 1).
    UnrestrictedFiltered,
    /// Filter path failed but the user answer was served (code 6).
    UnrestrictedUnknown,
    /// Safe-search domain-list hit; response taken from the filter path (code 8).
    SafeSearchEnforced,
    /// No filter path configured; user answer served (code 2).
    UnrestrictedUnFiltered,
    /// Always-allowable predicate (code 3).
    UnrestrictedAlwaysAllowable,
    /// Filter-path outage state; user resolvers served (code 7).
    UnrestrictedOutage,
    /// Both upstream paths timed out (code 12).
    TimedOut,
    /// Filter path timed out; user answer/fallback served (code 13).
    TimedOutFilter,
    /// User (system-resolver) path timed out (code 14).
    TimedOutSystem,
    /// Both upstream paths hard-failed (code 15).
    Failed,
}

impl VerdictType {
    /// The `dns_activity.resolution_type` string — byte-identical to the §8
    /// vocabulary.
    pub fn as_str(self) -> &'static str {
        match self {
            VerdictType::BlockedCustom => "BlockedCustom",
            VerdictType::BlockedGlobal => "BlockedGlobal",
            VerdictType::BlockedFilter => "BlockedFilter",
            VerdictType::UnrestrictedAllowCustom => "UnrestrictedAllowCustom",
            VerdictType::UnrestrictedAllowGlobal => "UnrestrictedAllowGlobal",
            VerdictType::UnrestrictedFiltered => "UnrestrictedFiltered",
            VerdictType::UnrestrictedUnknown => "UnrestrictedUnknown",
            VerdictType::SafeSearchEnforced => "SafeSearchEnforced",
            VerdictType::UnrestrictedUnFiltered => "UnrestrictedUnFiltered",
            VerdictType::UnrestrictedAlwaysAllowable => "UnrestrictedAlwaysAllowable",
            VerdictType::UnrestrictedOutage => "UnrestrictedOutage",
            VerdictType::TimedOut => "TimedOut",
            VerdictType::TimedOutFilter => "TimedOutFilter",
            VerdictType::TimedOutSystem => "TimedOutSystem",
            VerdictType::Failed => "Failed",
        }
    }

    /// CE's numeric mapper value (`filter-enforcement.md` verdict b table:
    /// 0xb, 10, 9, 5/4, 1/6, 8, 2/3, 7, 12–15).
    pub fn code(self) -> u8 {
        match self {
            VerdictType::UnrestrictedFiltered => 1,
            VerdictType::UnrestrictedUnFiltered => 2,
            VerdictType::UnrestrictedAlwaysAllowable => 3,
            VerdictType::UnrestrictedAllowGlobal => 4,
            VerdictType::UnrestrictedAllowCustom => 5,
            VerdictType::UnrestrictedUnknown => 6,
            VerdictType::UnrestrictedOutage => 7,
            VerdictType::SafeSearchEnforced => 8,
            VerdictType::BlockedFilter => 9,
            VerdictType::BlockedGlobal => 10,
            VerdictType::BlockedCustom => 0xb,
            VerdictType::TimedOut => 12,
            VerdictType::TimedOutFilter => 13,
            VerdictType::TimedOutSystem => 14,
            VerdictType::Failed => 15,
        }
    }

    /// All 15 codes, in §8 table order — used by the exhaustive table test.
    pub const ALL: [VerdictType; 15] = [
        VerdictType::BlockedCustom,
        VerdictType::BlockedGlobal,
        VerdictType::BlockedFilter,
        VerdictType::UnrestrictedAllowCustom,
        VerdictType::UnrestrictedAllowGlobal,
        VerdictType::UnrestrictedFiltered,
        VerdictType::UnrestrictedUnknown,
        VerdictType::SafeSearchEnforced,
        VerdictType::UnrestrictedUnFiltered,
        VerdictType::UnrestrictedAlwaysAllowable,
        VerdictType::UnrestrictedOutage,
        VerdictType::TimedOut,
        VerdictType::TimedOutFilter,
        VerdictType::TimedOutSystem,
        VerdictType::Failed,
    ];
}

/// The verdict of one query: the `resolution_type`, where the client's answer
/// comes from, and whether a block answer must be synthesized (§8).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct Verdict {
    /// The §8 `resolution_type` code.
    pub resolution_type: VerdictType,
    /// The response endpoint selector (filter / user / local).
    pub endpoint: ResponseEndpoint,
    /// `true` when the engine MUST replace the served answer with a
    /// synthesized block answer (`block.rs`, §8 "Block answers").
    pub block: bool,
}

/// Per-query inputs to [`decide`] (the `DnsProxyRequest` decision-tree state,
/// `filter-enforcement.md` mechanism §1.4).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct VerdictInput {
    /// Fail-closed "signed out ⇒ web blocked" policy flag (§8 lifecycle) —
    /// a LustLess extension: when set by the daemon (zero signed-in users +
    /// `dns.fail_closed_when_signed_out`), every query is blocked locally.
    pub fail_closed_block: bool,
    /// Custom-override tri-state for the queried domain.
    pub custom: OverrideVerdict,
    /// Global-override tri-state for the queried domain.
    pub global: OverrideVerdict,
    /// The queried domain hit the safe-search domain list (§8 code 8 trigger).
    pub safe_search_hit: bool,
    /// The queried domain matches the always-allowable predicate (§8 code 3).
    pub always_allowable: bool,
    /// The filter-path health machine reports an outage (§8 code 7 trigger).
    pub filter_outage: bool,
    /// Whether a filter path (DoH endpoint) is configured at all — CE's
    /// "no filter socket" branch (§8 code 2).
    pub filter_path_configured: bool,
    /// Outcome of the DoH filter-path resolution.
    pub filter: PathOutcome,
    /// Outcome of the user-resolver path resolution.
    pub user: PathOutcome,
}

/// The §8 decision tree. Precedence (documented mapping of CE's
/// `processDnsRequest` flow onto explicit inputs):
///
/// 1. fail-closed block → `BlockedCustom` (local synthesis)
/// 2. custom override block → `BlockedCustom` (local synthesis)
/// 3. custom override allow → `UnrestrictedAllowCustom` (user answer)
/// 4. global override block → `BlockedGlobal` (local synthesis)
/// 5. global override allow → `UnrestrictedAllowGlobal` (user answer)
/// 6. filter outage → `UnrestrictedOutage` on a user answer, else the
///    timeout/failure classification of the (dead) paths
/// 7. safe-search hit → `SafeSearchEnforced` with the **filter** answer
///    (§8: "response taken from the filter-side answer"); a filter block
///    marker still dominates → `BlockedFilter`
/// 8. always-allowable predicate → `UnrestrictedAlwaysAllowable`
/// 9. no filter path → `UnrestrictedUnFiltered` / user-side timeout classes
/// 10. filter answer: RPZ marker → `BlockedFilter` (local synthesis),
///     otherwise `UnrestrictedFiltered` (filter answer served)
/// 11. filter path dead: `TimedOut` / `TimedOutFilter` / `TimedOutSystem` /
///     `UnrestrictedUnknown` / `Failed` per the §8 12–15 failure matrix
pub fn decide(input: &VerdictInput) -> Verdict {
    use OverrideVerdict::*;
    use PathOutcome::*;
    use ResponseEndpoint::*;
    use VerdictType::*;

    let filter_marker = match &input.filter {
        Answer(bytes) => answer_is_filter_block(bytes),
        _ => false,
    };

    // 1–5: overrides and the fail-closed policy flag outrank everything.
    if input.fail_closed_block {
        return Verdict { resolution_type: BlockedCustom, endpoint: Local, block: true };
    }
    match input.custom {
        Block => return Verdict { resolution_type: BlockedCustom, endpoint: Local, block: true },
        Allow => {
            return Verdict { resolution_type: UnrestrictedAllowCustom, endpoint: User, block: false }
        }
        NotApplicable => {}
    }
    match input.global {
        Block => return Verdict { resolution_type: BlockedGlobal, endpoint: Local, block: true },
        Allow => {
            return Verdict { resolution_type: UnrestrictedAllowGlobal, endpoint: User, block: false }
        }
        NotApplicable => {}
    }

    // 6: outage — CE falls back to the user's resolvers with code 7.
    if input.filter_outage {
        return match &input.user {
            Answer(_) => {
                Verdict { resolution_type: UnrestrictedOutage, endpoint: User, block: false }
            }
            Timeout => Verdict { resolution_type: TimedOutSystem, endpoint: User, block: false },
            Failure => Verdict { resolution_type: Failed, endpoint: User, block: false },
        };
    }

    // 7: safe-search — the hit switches the response endpoint to the filter
    // answer; a block marker in that answer still means BlockedFilter.
    if input.safe_search_hit && matches!(&input.filter, Answer(_)) {
        if filter_marker {
            return Verdict { resolution_type: BlockedFilter, endpoint: Local, block: true };
        }
        return Verdict { resolution_type: SafeSearchEnforced, endpoint: Filter, block: false };
    }

    // 8: always-allowable predicate.
    if input.always_allowable {
        return Verdict { resolution_type: UnrestrictedAlwaysAllowable, endpoint: User, block: false };
    }

    // 9: no filter path configured at all (CE "no filter socket" branch).
    if !input.filter_path_configured {
        return match &input.user {
            Answer(_) => {
                Verdict { resolution_type: UnrestrictedUnFiltered, endpoint: User, block: false }
            }
            Timeout => Verdict { resolution_type: TimedOutSystem, endpoint: User, block: false },
            Failure => Verdict { resolution_type: Failed, endpoint: User, block: false },
        };
    }

    // 10/11: filter answer vs. upstream failure matrix.
    match (&input.filter, &input.user) {
        (Answer(_), _) if filter_marker => {
            Verdict { resolution_type: BlockedFilter, endpoint: Local, block: true }
        }
        (Answer(_), _) => Verdict { resolution_type: UnrestrictedFiltered, endpoint: Filter, block: false },
        (Timeout, Answer(_)) => Verdict { resolution_type: TimedOutFilter, endpoint: User, block: false },
        (Timeout, Timeout) => Verdict { resolution_type: TimedOut, endpoint: User, block: false },
        (Timeout, Failure) => Verdict { resolution_type: TimedOutFilter, endpoint: User, block: false },
        (Failure, Answer(_)) => {
            Verdict { resolution_type: UnrestrictedUnknown, endpoint: User, block: false }
        }
        (Failure, Timeout) => Verdict { resolution_type: TimedOutSystem, endpoint: User, block: false },
        (Failure, Failure) => Verdict { resolution_type: Failed, endpoint: User, block: false },
    }
}

/// `true` when an upstream wire answer carries the §8 `BlockedFilter` RPZ
/// marker: any answer or authority record whose owner name or CNAME target is
/// at-or-under [`RPZ_BLOCK_MARKER`] (case-insensitive label comparison by
/// hickory). Unparseable bytes are not a block.
pub fn answer_is_filter_block(answer: &[u8]) -> bool {
    match Message::from_vec(answer) {
        Ok(message) => message_contains_marker(&message),
        Err(_) => false,
    }
}

fn message_contains_marker(message: &Message) -> bool {
    let Ok(marker) = Name::from_ascii(RPZ_BLOCK_MARKER) else {
        return false;
    };
    for record in message.answers().iter().chain(message.name_servers().iter()) {
        if marker.zone_of(record.name()) {
            return true;
        }
        if let RData::CNAME(cname) = record.data() {
            if marker.zone_of(&cname.0) {
                return true;
            }
        }
    }
    false
}

#[cfg(test)]
mod tests {
    use super::*;
    use hickory_proto::op::{MessageType, OpCode, Query, ResponseCode};
    use hickory_proto::rr::rdata::{A, AAAA, CNAME};
    use hickory_proto::rr::{Record, RecordType};
    use std::net::{Ipv4Addr, Ipv6Addr};

    /// Neutral inputs: no overrides, no policy hits, both paths answering
    /// cleanly. Individual tests perturb one field at a time.
    fn base_input() -> VerdictInput {
        VerdictInput {
            fail_closed_block: false,
            custom: OverrideVerdict::NotApplicable,
            global: OverrideVerdict::NotApplicable,
            safe_search_hit: false,
            always_allowable: false,
            filter_outage: false,
            filter_path_configured: true,
            filter: PathOutcome::Answer(clean_answer()),
            user: PathOutcome::Answer(clean_answer()),
        }
    }

    fn clean_answer() -> Vec<u8> {
        answer_with_cname_target("cdn.example.net.")
    }

    fn answer_with_cname_target(target: &str) -> Vec<u8> {
        let mut msg = Message::new();
        msg.set_id(0x4242);
        msg.set_message_type(MessageType::Response);
        msg.set_op_code(OpCode::Query);
        msg.set_recursion_desired(true);
        msg.set_response_code(ResponseCode::NoError);
        msg.add_query(Query::query(Name::from_ascii("example.com").unwrap(), RecordType::A));
        msg.add_answer(Record::from_rdata(
            Name::from_ascii("example.com").unwrap(),
            60,
            RData::CNAME(CNAME(Name::from_ascii(target).unwrap())),
        ));
        msg.add_answer(Record::from_rdata(
            Name::from_ascii(target).unwrap(),
            60,
            RData::A(A(Ipv4Addr::new(10, 20, 30, 40))),
        ));
        msg.to_vec().unwrap()
    }

    fn rpz_answer() -> Vec<u8> {
        answer_with_cname_target("blocked.cleanbrowsing.rpz.noc.org.")
    }

    /// The §8 table, verbatim: every code string and numeric value.
    #[test]
    fn verdict_table_is_byte_identical_to_contract_s8() {
        let expected: [(VerdictType, &str, u8); 15] = [
            (VerdictType::BlockedCustom, "BlockedCustom", 0xb),
            (VerdictType::BlockedGlobal, "BlockedGlobal", 10),
            (VerdictType::BlockedFilter, "BlockedFilter", 9),
            (VerdictType::UnrestrictedAllowCustom, "UnrestrictedAllowCustom", 5),
            (VerdictType::UnrestrictedAllowGlobal, "UnrestrictedAllowGlobal", 4),
            (VerdictType::UnrestrictedFiltered, "UnrestrictedFiltered", 1),
            (VerdictType::UnrestrictedUnknown, "UnrestrictedUnknown", 6),
            (VerdictType::SafeSearchEnforced, "SafeSearchEnforced", 8),
            (VerdictType::UnrestrictedUnFiltered, "UnrestrictedUnFiltered", 2),
            (VerdictType::UnrestrictedAlwaysAllowable, "UnrestrictedAlwaysAllowable", 3),
            (VerdictType::UnrestrictedOutage, "UnrestrictedOutage", 7),
            (VerdictType::TimedOut, "TimedOut", 12),
            (VerdictType::TimedOutFilter, "TimedOutFilter", 13),
            (VerdictType::TimedOutSystem, "TimedOutSystem", 14),
            (VerdictType::Failed, "Failed", 15),
        ];
        assert_eq!(VerdictType::ALL.len(), 15);
        for (variant, name, code) in expected {
            assert_eq!(variant.as_str(), name);
            assert_eq!(variant.code(), code);
            assert!(VerdictType::ALL.contains(&variant));
        }
        // No drift: as_str is injective over ALL.
        let mut strings: Vec<&str> = VerdictType::ALL.iter().map(|v| v.as_str()).collect();
        let len = strings.len();
        strings.sort_unstable();
        strings.dedup();
        assert_eq!(strings.len(), len);
    }

    #[test]
    fn tri_state_overrides_map_per_ce() {
        assert_eq!(OverrideVerdict::from_tristate(0), OverrideVerdict::Allow);
        assert_eq!(OverrideVerdict::from_tristate(1), OverrideVerdict::Block);
        assert_eq!(OverrideVerdict::from_tristate(2), OverrideVerdict::NotApplicable);
        assert_eq!(OverrideVerdict::from_tristate(9), OverrideVerdict::NotApplicable);
    }

    #[test]
    fn clean_filter_answer_is_unrestricted_filtered() {
        let verdict = decide(&base_input());
        assert_eq!(verdict.resolution_type, VerdictType::UnrestrictedFiltered);
        assert_eq!(verdict.endpoint, ResponseEndpoint::Filter);
        assert!(!verdict.block);
    }

    #[test]
    fn custom_override_block_wins() {
        let mut input = base_input();
        input.custom = OverrideVerdict::Block;
        let verdict = decide(&input);
        assert_eq!(verdict.resolution_type, VerdictType::BlockedCustom);
        assert_eq!(verdict.endpoint, ResponseEndpoint::Local);
        assert!(verdict.block);
    }

    #[test]
    fn custom_override_allow_beats_global_block() {
        let mut input = base_input();
        input.custom = OverrideVerdict::Allow;
        input.global = OverrideVerdict::Block;
        let verdict = decide(&input);
        assert_eq!(verdict.resolution_type, VerdictType::UnrestrictedAllowCustom);
        assert_eq!(verdict.endpoint, ResponseEndpoint::User);
        assert!(!verdict.block);
    }

    #[test]
    fn global_override_block_and_allow() {
        let mut input = base_input();
        input.global = OverrideVerdict::Block;
        let verdict = decide(&input);
        assert_eq!(verdict.resolution_type, VerdictType::BlockedGlobal);
        assert!(verdict.block);
        input.global = OverrideVerdict::Allow;
        let verdict = decide(&input);
        assert_eq!(verdict.resolution_type, VerdictType::UnrestrictedAllowGlobal);
        assert_eq!(verdict.endpoint, ResponseEndpoint::User);
    }

    #[test]
    fn rpz_marker_in_filter_answer_is_blocked_filter() {
        let mut input = base_input();
        input.filter = PathOutcome::Answer(rpz_answer());
        let verdict = decide(&input);
        assert_eq!(verdict.resolution_type, VerdictType::BlockedFilter);
        assert_eq!(verdict.endpoint, ResponseEndpoint::Local);
        assert!(verdict.block);
    }

    #[test]
    fn safe_search_hit_serves_the_filter_answer() {
        let mut input = base_input();
        input.safe_search_hit = true;
        let verdict = decide(&input);
        assert_eq!(verdict.resolution_type, VerdictType::SafeSearchEnforced);
        assert_eq!(verdict.endpoint, ResponseEndpoint::Filter);
        assert!(!verdict.block);
    }

    #[test]
    fn safe_search_hit_with_rpz_marker_is_blocked_filter() {
        let mut input = base_input();
        input.safe_search_hit = true;
        input.filter = PathOutcome::Answer(rpz_answer());
        let verdict = decide(&input);
        assert_eq!(verdict.resolution_type, VerdictType::BlockedFilter);
        assert!(verdict.block);
    }

    #[test]
    fn safe_search_hit_without_filter_answer_degrades_to_timeout_class() {
        let mut input = base_input();
        input.safe_search_hit = true;
        input.filter = PathOutcome::Timeout;
        let verdict = decide(&input);
        assert_eq!(verdict.resolution_type, VerdictType::TimedOutFilter);
    }

    #[test]
    fn always_allowable_predicate() {
        let mut input = base_input();
        input.always_allowable = true;
        let verdict = decide(&input);
        assert_eq!(verdict.resolution_type, VerdictType::UnrestrictedAlwaysAllowable);
        assert_eq!(verdict.endpoint, ResponseEndpoint::User);
    }

    #[test]
    fn no_filter_path_is_unrestricted_unfiltered() {
        let mut input = base_input();
        input.filter_path_configured = false;
        input.filter = PathOutcome::Failure;
        let verdict = decide(&input);
        assert_eq!(verdict.resolution_type, VerdictType::UnrestrictedUnFiltered);
        assert_eq!(verdict.endpoint, ResponseEndpoint::User);
    }

    #[test]
    fn no_filter_path_with_user_timeout_or_failure() {
        let mut input = base_input();
        input.filter_path_configured = false;
        input.filter = PathOutcome::Failure;
        input.user = PathOutcome::Timeout;
        assert_eq!(decide(&input).resolution_type, VerdictType::TimedOutSystem);
        input.user = PathOutcome::Failure;
        assert_eq!(decide(&input).resolution_type, VerdictType::Failed);
    }

    #[test]
    fn outage_falls_back_to_user_path() {
        let mut input = base_input();
        input.filter_outage = true;
        input.filter = PathOutcome::Failure;
        let verdict = decide(&input);
        assert_eq!(verdict.resolution_type, VerdictType::UnrestrictedOutage);
        assert_eq!(verdict.endpoint, ResponseEndpoint::User);
        assert!(!verdict.block);
        input.user = PathOutcome::Timeout;
        assert_eq!(decide(&input).resolution_type, VerdictType::TimedOutSystem);
        input.user = PathOutcome::Failure;
        assert_eq!(decide(&input).resolution_type, VerdictType::Failed);
    }

    #[test]
    fn fail_closed_flag_blocks_everything_first() {
        let mut input = base_input();
        input.fail_closed_block = true;
        input.custom = OverrideVerdict::Allow;
        input.always_allowable = true;
        let verdict = decide(&input);
        assert_eq!(verdict.resolution_type, VerdictType::BlockedCustom);
        assert!(verdict.block);
    }

    /// The §8 12–15 failure matrix, exhaustively — deterministic (jitter-free)
    /// classification of every (filter, user) outcome pair.
    #[test]
    fn timeout_and_failure_matrix_is_exhaustive_and_deterministic() {
        use PathOutcome::*;
        let outcomes = [
            Answer(clean_answer()),
            Timeout,
            Failure,
        ];
        let mut seen = std::collections::HashSet::new();
        for filter in &outcomes {
            for user in &outcomes {
                let input = VerdictInput {
                    filter: filter.clone(),
                    user: user.clone(),
                    ..base_input()
                };
                let first = decide(&input);
                let second = decide(&input);
                assert_eq!(first, second, "verdict must be a pure function");
                seen.insert(first.resolution_type);
            }
        }
        // Every failure-class code is reachable from some outcome pair.
        for code in [
            VerdictType::UnrestrictedFiltered,
            VerdictType::UnrestrictedUnknown,
            VerdictType::TimedOut,
            VerdictType::TimedOutFilter,
            VerdictType::TimedOutSystem,
            VerdictType::Failed,
        ] {
            assert!(seen.contains(&code), "missing {code:?}");
        }
        // Spot-check the §8 mapping of the timeout rows.
        let case = |filter, user| {
            decide(&VerdictInput { filter, user, ..base_input() }).resolution_type
        };
        assert_eq!(case(Timeout, Answer(clean_answer())), VerdictType::TimedOutFilter);
        assert_eq!(case(Timeout, Timeout), VerdictType::TimedOut);
        assert_eq!(case(Timeout, Failure), VerdictType::TimedOutFilter);
        assert_eq!(case(Failure, Answer(clean_answer())), VerdictType::UnrestrictedUnknown);
        assert_eq!(case(Failure, Timeout), VerdictType::TimedOutSystem);
        assert_eq!(case(Failure, Failure), VerdictType::Failed);
    }

    #[test]
    fn rpz_marker_detection_cases() {
        assert!(answer_is_filter_block(&rpz_answer()));
        // Exact marker as the owner name also counts.
        let exact = answer_with_cname_target("cleanbrowsing.rpz.noc.org.");
        assert!(answer_is_filter_block(&exact));
        // Clean answers do not.
        assert!(!answer_is_filter_block(&clean_answer()));
        // Case-insensitive.
        let mixed = answer_with_cname_target("Blocked.CleanBrowsing.RPZ.NOC.Org.");
        assert!(answer_is_filter_block(&mixed));
        // Sibling domains are not the marker.
        let sibling = answer_with_cname_target("rpz.noc.org.");
        assert!(!answer_is_filter_block(&sibling));
        // Unparseable bytes are not a block.
        assert!(!answer_is_filter_block(&[0x12, 0x34, 0xFF]));
        assert!(!answer_is_filter_block(&[]));
    }

    #[test]
    fn marker_in_authority_section_counts() {
        let mut msg = Message::new();
        msg.set_id(1);
        msg.set_message_type(MessageType::Response);
        msg.set_op_code(OpCode::Query);
        msg.set_response_code(ResponseCode::NoError);
        msg.add_query(Query::query(Name::from_ascii("bad.example").unwrap(), RecordType::A));
        msg.add_name_server(Record::from_rdata(
            Name::from_ascii("cleanbrowsing.rpz.noc.org").unwrap(),
            60,
            RData::A(A(Ipv4Addr::LOCALHOST)),
        ));
        assert!(answer_is_filter_block(&msg.to_vec().unwrap()));
    }

    #[test]
    fn answer_bytes_accessor() {
        assert_eq!(PathOutcome::Answer(vec![1]).answer_bytes(), Some(&[1u8][..]));
        assert_eq!(PathOutcome::Timeout.answer_bytes(), None);
        assert_eq!(PathOutcome::Failure.answer_bytes(), None);
    }

    /// Guard against accidentally widening the AAAA path without updating the
    /// marker logic (CNAME extraction is the only rdata the detector reads).
    #[test]
    fn aaaa_answers_are_handled() {
        let mut msg = Message::new();
        msg.set_id(2);
        msg.set_message_type(MessageType::Response);
        msg.set_op_code(OpCode::Query);
        msg.set_response_code(ResponseCode::NoError);
        msg.add_query(Query::query(Name::from_ascii("example.com").unwrap(), RecordType::AAAA));
        msg.add_answer(Record::from_rdata(
            Name::from_ascii("example.com").unwrap(),
            60,
            RData::AAAA(AAAA(Ipv6Addr::LOCALHOST)),
        ));
        let wire = msg.to_vec().unwrap();
        assert!(!answer_is_filter_block(&wire));
    }
}
