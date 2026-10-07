//! Exact-ID approval-rule selection — a port of `packages/verify/src/approval-policy.ts`, version 3
//! (stable action IDs) only, which is what an offline trust bundle uses (DIV §5a.4).
//!
//! Display text is never an authorization input here: a rule is selected by its exact action ID, or
//! the `*` baseline when the signed `unmatchedActionPolicy` says `BASELINE`. The legacy substring
//! ranking (versions 1 and 2) is deliberately not ported — no offline bundle may use it.
//!
//! The whole policy is validated before any rule is chosen, so a corrupt or conflicting rule for one
//! action cannot hide behind a valid one for another.

use std::fmt;

use crate::trust_bundle::{BundlePolicy, UnmatchedActionPolicy};

/// `Number.MAX_SAFE_INTEGER`: the reference's integers are JavaScript numbers.
pub(crate) const MAX_SAFE_INTEGER: i64 = 9_007_199_254_740_991;

/// The policy cannot be resolved unambiguously. `fields` names what conflicts, in the reference's
/// spelling (`requiredApprovals`, `approverDids`, `missingBaseline`, …).
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ApprovalPolicyConflict {
    pub fields: Vec<String>,
}

impl ApprovalPolicyConflict {
    fn new<S: Into<String>>(fields: impl IntoIterator<Item = S>) -> Self {
        ApprovalPolicyConflict {
            fields: fields.into_iter().map(Into::into).collect(),
        }
    }
}

impl fmt::Display for ApprovalPolicyConflict {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        write!(
            f,
            "Conflicting approval requirements: {}",
            self.fields.join(", ")
        )
    }
}

impl std::error::Error for ApprovalPolicyConflict {}

/// A stable action ID: `^[A-Za-z][A-Za-z0-9]*(?:[._:/-][A-Za-z0-9]+)*$`, at most 200 characters.
pub fn valid_approval_action_id(value: &str) -> bool {
    let b = value.as_bytes();
    if b.is_empty() || b.len() > 200 || !b[0].is_ascii_alphabetic() {
        return false;
    }
    let separator = |c: u8| matches!(c, b'.' | b'_' | b':' | b'/' | b'-');
    let mut previous_was_separator = false;
    for &c in &b[1..] {
        if separator(c) {
            if previous_was_separator {
                return false;
            }
            previous_was_separator = true;
        } else if c.is_ascii_alphanumeric() {
            previous_was_separator = false;
        } else {
            return false;
        }
    }
    !previous_was_separator
}

fn safe_positive(n: i64) -> bool {
    (1..=MAX_SAFE_INTEGER).contains(&n)
}

/// Validate the whole policy: every pattern a valid ID or `*`, no duplicate (case-insensitively), a
/// quorum of at least 1, a `*` baseline whenever there are rules, and no rule that drops a baseline
/// constraint.
pub fn validate_exact_approval_policy(
    rules: &[BundlePolicy],
) -> Result<(), ApprovalPolicyConflict> {
    let mut seen: Vec<String> = Vec::with_capacity(rules.len());
    for rule in rules {
        let lower = rule.action_pattern.to_lowercase();
        if (rule.action_pattern != "*" && !valid_approval_action_id(&rule.action_pattern))
            || !safe_positive(rule.required_approvals)
            || seen.contains(&lower)
        {
            return Err(ApprovalPolicyConflict::new(["invalidOrDuplicateActionId"]));
        }
        seen.push(lower);
    }
    if !rules.is_empty() && !seen.iter().any(|p| p == "*") {
        return Err(ApprovalPolicyConflict::new(["missingBaseline"]));
    }
    let Some(baseline) = rules.iter().find(|r| r.action_pattern == "*") else {
        return Ok(());
    };
    for rule in rules {
        let fields = lost_approval_constraints(rule, baseline);
        if !fields.is_empty() {
            return Err(ApprovalPolicyConflict::new(fields));
        }
    }
    Ok(())
}

fn subset(a: &[String], b: &[String]) -> bool {
    a.iter().all(|v| b.contains(v))
}

fn same_set(a: &[String], b: &[String]) -> bool {
    subset(a, b) && subset(b, a)
}

fn truthy(s: &Option<String>) -> bool {
    s.as_deref().is_some_and(|v| !v.is_empty())
}

type WindowKey<'a> = (
    Option<&'a str>,
    Option<i64>,
    Option<&'a str>,
    Option<&'a str>,
);

fn window_key(r: &BundlePolicy) -> WindowKey<'_> {
    (
        r.auto_approve_requester_did.as_deref(),
        r.auto_approve_day_of_week,
        r.auto_approve_window_start.as_deref(),
        r.auto_approve_window_end.as_deref(),
    )
}

/// Which of `other`'s constraints `selected` would lose. Empty eligible lists denote the same owner
/// fallback, NOT unrestricted eligibility.
pub fn lost_approval_constraints(
    selected: &BundlePolicy,
    other: &BundlePolicy,
) -> Vec<&'static str> {
    let mut lost = Vec::new();
    if selected.required_approvals < other.required_approvals {
        lost.push("requiredApprovals");
    }
    if other.require_hardware_key && !selected.require_hardware_key {
        lost.push("requireHardwareKey");
    }
    if other.requester_cannot_approve && !selected.requester_cannot_approve {
        lost.push("requesterCannotApprove");
    }
    if other.require_attested_requester && !selected.require_attested_requester {
        lost.push("requireAttestedRequester");
    }
    for (field, a, b) in [
        (
            "allowedAaguids",
            &selected.allowed_aaguids,
            &other.allowed_aaguids,
        ),
        (
            "allowedIssuers",
            &selected.allowed_issuers,
            &other.allowed_issuers,
        ),
    ] {
        if !b.is_empty() && (a.is_empty() || !subset(a, b)) {
            lost.push(field);
        }
    }
    let none: Vec<String> = Vec::new();
    // Different unresolved groups cannot be compared safely.
    if !same_set(
        selected.approver_group_ids.as_ref().unwrap_or(&none),
        other.approver_group_ids.as_ref().unwrap_or(&none),
    ) {
        lost.push("approverGroups");
    }
    let (a, b) = (&selected.approver_dids, &other.approver_dids);
    if a.is_empty() != b.is_empty() || !subset(a, b) {
        lost.push("approverDids");
    }
    // Escalation widens eligibility with time: require the same schedule and the same added set.
    if selected.escalate_after_seconds != other.escalate_after_seconds
        || !same_set(
            &selected.escalation_approver_dids,
            &other.escalation_approver_dids,
        )
        || !same_set(
            selected.escalation_group_ids.as_ref().unwrap_or(&none),
            other.escalation_group_ids.as_ref().unwrap_or(&none),
        )
    {
        lost.push("escalation");
    }
    if (truthy(&selected.auto_approve_requester_did) || truthy(&other.auto_approve_requester_did))
        && (window_key(selected) != window_key(other)
            || selected.required_approvals != other.required_approvals
            || selected.require_hardware_key != other.require_hardware_key
            || selected.requester_cannot_approve != other.requester_cannot_approve
            || selected.require_attested_requester != other.require_attested_requester
            || !same_set(a, b)
            || !same_set(&selected.allowed_aaguids, &other.allowed_aaguids)
            || !same_set(&selected.allowed_issuers, &other.allowed_issuers))
    {
        lost.push("autoApproval");
    }
    lost
}

/// Select the rule for `action_type` with the exact-ID (version 3) algorithm.
///
/// `Err` when the policy conflicts or a differently cased spelling of a configured ID is used — a
/// protected ID must not fall through to a weaker baseline. `Ok(None)` when the action is invalid or
/// unmatched under `DENY`. `display` is accepted for parity with the reference signature and is
/// never consulted.
pub fn select_approval_rule<'a>(
    rules: &'a [BundlePolicy],
    action_type: &str,
    _display: &str,
    unmatched: UnmatchedActionPolicy,
) -> Result<Option<&'a BundlePolicy>, ApprovalPolicyConflict> {
    validate_exact_approval_policy(rules)?;
    if action_type.is_empty() || !valid_approval_action_id(action_type) {
        return Ok(None);
    }
    let lower = action_type.to_lowercase();
    if rules.iter().any(|r| {
        r.action_pattern != "*"
            && r.action_pattern != action_type
            && r.action_pattern.to_lowercase() == lower
    }) {
        return Err(ApprovalPolicyConflict::new(["actionIdCaseMismatch"]));
    }
    Ok(rules
        .iter()
        .find(|r| r.action_pattern == action_type)
        .or_else(|| match unmatched {
            UnmatchedActionPolicy::Baseline => rules.iter().find(|r| r.action_pattern == "*"),
            UnmatchedActionPolicy::Deny => None,
        }))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn action_id_grammar() {
        for ok in ["a", "db.restart", "A1", "x:y/z-w_v", "wire.transfer"] {
            assert!(valid_approval_action_id(ok), "{ok}");
        }
        for bad in [
            "",
            "1a",
            ".a",
            "a.",
            "a..b",
            "db restart",
            "a-",
            "é",
            &"a".repeat(201),
        ] {
            assert!(!valid_approval_action_id(bad), "{bad}");
        }
        assert!(valid_approval_action_id(&"a".repeat(200)));
    }
}
