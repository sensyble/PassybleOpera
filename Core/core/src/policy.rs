//! Organisation policies: what a team or family requires of its members' apps, checked against
//! the device's own settings. The core only says what is wrong; the apps enforce it. Every key is
//! optional and unknown keys are ignored, so a later service can add rules older apps skip:
//!
//! ```json
//! { "master_password_min_strength": "good",   // or 0 to 4: very weak, weak, fair, good, strong
//!   "max_auto_lock_minutes": 15,
//!   "export_allowed": false,
//!   "sharing_outside_allowed": false,
//!   "require_two_step": true }
//! ```

use serde::{Deserialize, Serialize};

use crate::i18n::tr;
use crate::{PassError, Result};

/// A parsed policy ([`policy_parse`]). The defaults require nothing.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct OrgPolicy {
    /// The weakest master password allowed, as [`crate::PasswordStrength::score`] (0 to 4); 0
    /// allows any.
    pub min_master_password_score: u32,
    /// The longest auto-lock allowed, in seconds; `None` for no limit.
    pub max_auto_lock_secs: Option<u64>,
    /// Whether the org's shared vaults may be exported.
    pub export_allowed: bool,
    /// Whether members may share items with people outside the organisation (a direct share
    /// with an account that isn't a member).
    pub sharing_outside_allowed: bool,
    /// Whether the Passyble account must sign in with a passkey or a second step.
    pub require_two_step: bool,
}

impl Default for OrgPolicy {
    fn default() -> Self {
        OrgPolicy {
            min_master_password_score: 0,
            max_auto_lock_secs: None,
            export_allowed: true,
            sharing_outside_allowed: true,
            require_two_step: false,
        }
    }
}

/// The device's settings a policy is checked against.
#[derive(Clone, Debug, PartialEq, Eq, Default, Serialize, Deserialize)]
#[serde(default)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct LocalSecurity {
    /// [`crate::PasswordStrength::score`] of the master password, measured when it was last
    /// typed; `None` when not known yet (no violation until it is).
    pub master_password_score: Option<u32>,
    /// The auto-lock in seconds; `None` when the vault never locks by itself.
    pub auto_lock_secs: Option<u64>,
    /// Whether the Passyble account signs in with a passkey or a second step.
    pub two_step_enabled: bool,
}

/// Which rule a violation breaks.
#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum PolicyRule {
    MasterPasswordStrength,
    AutoLock,
    TwoStep,
}

/// One setting of this device that a policy doesn't allow.
#[derive(Clone, Debug, PartialEq, Eq, Serialize, Deserialize)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Record))]
pub struct PolicyViolation {
    pub rule: PolicyRule,
    /// What to tell the user, in the core's language.
    pub message: String,
}

#[derive(Deserialize)]
#[serde(untagged)]
enum Strength {
    Score(u32),
    Label(String),
}

#[derive(Deserialize, Default)]
struct PolicyFile {
    master_password_min_strength: Option<Strength>,
    max_auto_lock_minutes: Option<u64>,
    export_allowed: Option<bool>,
    sharing_outside_allowed: Option<bool>,
    require_two_step: Option<bool>,
}

fn bad_policy() -> PassError {
    PassError::InvalidInput(tr!("policy.bad"))
}

fn score_of(label: &str) -> Option<u32> {
    Some(match label {
        "very_weak" => 0,
        "weak" => 1,
        "fair" => 2,
        "good" => 3,
        "strong" => 4,
        _ => return None,
    })
}

/// Parses a policy. An unknown strength label reads as the strongest (a later service's
/// stricter level is not taken for no requirement); `InvalidInput` for JSON that isn't an
/// object of the documented shape.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn policy_parse(json: &str) -> Result<OrgPolicy> {
    let file: PolicyFile = serde_json::from_str(json).map_err(|_| bad_policy())?;
    let defaults = OrgPolicy::default();
    Ok(OrgPolicy {
        min_master_password_score: match file.master_password_min_strength {
            None => 0,
            Some(Strength::Score(s)) => s.min(4),
            Some(Strength::Label(l)) => score_of(&l).unwrap_or(4),
        },
        max_auto_lock_secs: file.max_auto_lock_minutes.map(|m| m.saturating_mul(60)),
        export_allowed: file.export_allowed.unwrap_or(defaults.export_allowed),
        sharing_outside_allowed: file
            .sharing_outside_allowed
            .unwrap_or(defaults.sharing_outside_allowed),
        require_two_step: file.require_two_step.unwrap_or(defaults.require_two_step),
    })
}

/// The strictest of several policies (a member of a team and a family): the highest strength,
/// the shortest auto-lock, export and outside sharing only if every policy allows them, two
/// steps if any requires it.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn policy_strictest(policies: Vec<OrgPolicy>) -> OrgPolicy {
    policies
        .into_iter()
        .fold(OrgPolicy::default(), |a, b| OrgPolicy {
            min_master_password_score: a.min_master_password_score.max(b.min_master_password_score),
            max_auto_lock_secs: match (a.max_auto_lock_secs, b.max_auto_lock_secs) {
                (Some(x), Some(y)) => Some(x.min(y)),
                (x, y) => x.or(y),
            },
            export_allowed: a.export_allowed && b.export_allowed,
            sharing_outside_allowed: a.sharing_outside_allowed && b.sharing_outside_allowed,
            require_two_step: a.require_two_step || b.require_two_step,
        })
}

fn strength_name(score: u32) -> String {
    match crate::password_check::strength_label(score) {
        "very_weak" => tr!("policy.strength_very_weak"),
        "weak" => tr!("policy.strength_weak"),
        "fair" => tr!("policy.strength_fair"),
        "good" => tr!("policy.strength_good"),
        _ => tr!("policy.strength_strong"),
    }
}

/// What this device's settings break of `policy`, for the apps to fix or enforce. Empty when
/// everything is allowed.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn policy_violations(policy: OrgPolicy, local: LocalSecurity) -> Vec<PolicyViolation> {
    let mut out = Vec::new();
    if let Some(score) = local.master_password_score {
        if score < policy.min_master_password_score {
            out.push(PolicyViolation {
                rule: PolicyRule::MasterPasswordStrength,
                message: tr!(
                    "policy.weak_master_password",
                    strength = strength_name(policy.min_master_password_score)
                ),
            });
        }
    }
    if let Some(max) = policy.max_auto_lock_secs {
        if local.auto_lock_secs.is_none_or(|secs| secs > max) {
            out.push(PolicyViolation {
                rule: PolicyRule::AutoLock,
                message: crate::i18n::trn!("policy.auto_lock_too_long", max.div_ceil(60).max(1)),
            });
        }
    }
    if policy.require_two_step && !local.two_step_enabled {
        out.push(PolicyViolation {
            rule: PolicyRule::TwoStep,
            message: tr!("policy.two_step_required"),
        });
    }
    out
}

/// Whether a new master password meets `policy`: the violation to show, `None` when it does.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn policy_check_master_password(
    policy: OrgPolicy,
    password: String,
) -> Option<PolicyViolation> {
    let password = zeroize::Zeroizing::new(password);
    let score = crate::health::strength_of(&password).score;
    policy_violations(
        policy,
        LocalSecurity {
            master_password_score: Some(score),
            auto_lock_secs: Some(0),
            two_step_enabled: true,
        },
    )
    .into_iter()
    .next()
}

/// The auto-lock to use: the user's choice, shortened to what `policy` allows (`None`: never
/// lock, only without a limit).
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn policy_auto_lock_secs(policy: OrgPolicy, chosen: Option<u64>) -> Option<u64> {
    match (chosen, policy.max_auto_lock_secs) {
        (Some(c), Some(max)) => Some(c.min(max)),
        (None, max) => max,
        (c, None) => c,
    }
}

/// Whether the vaults under `policy` may be exported. `None` (a personal vault, no organisation)
/// always may. The apps hide Export otherwise; the message is `policy.export_blocked`.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn policy_allows_export(policy: Option<OrgPolicy>) -> bool {
    policy.is_none_or(|p| p.export_allowed)
}

/// Whether a direct share with `recipient_in_org` (the other account is a member of the same
/// organisation) is allowed: sharing outside it only if the policy allows it. `None` (no
/// organisation) always allows.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn policy_allows_share(policy: Option<OrgPolicy>, recipient_in_org: bool) -> bool {
    recipient_in_org || policy.is_none_or(|p| p.sharing_outside_allowed)
}

/// The text the apps show when [`policy_allows_export`] or [`policy_allows_share`] says no.
#[cfg_attr(feature = "uniffi", uniffi::export)]
pub fn policy_blocked_message(rule: PolicyBlock) -> String {
    match rule {
        PolicyBlock::Export => tr!("policy.export_blocked"),
        PolicyBlock::SharingOutside => tr!("policy.sharing_outside_blocked"),
    }
}

/// An action a policy can forbid ([`policy_blocked_message`]).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
#[cfg_attr(feature = "uniffi", derive(uniffi::Enum))]
pub enum PolicyBlock {
    Export,
    SharingOutside,
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn a_policy_parses_with_labels_numbers_and_unknown_keys() {
        let p = policy_parse(
            r#"{"master_password_min_strength":"good","max_auto_lock_minutes":15,
                "export_allowed":false,"sharing_outside_allowed":false,
                "require_two_step":true,"later_rule":{"x":1}}"#,
        )
        .unwrap();
        assert_eq!(
            p,
            OrgPolicy {
                min_master_password_score: 3,
                max_auto_lock_secs: Some(900),
                export_allowed: false,
                sharing_outside_allowed: false,
                require_two_step: true,
            }
        );
        assert_eq!(policy_parse("{}").unwrap(), OrgPolicy::default());
        assert_eq!(
            policy_parse(r#"{"master_password_min_strength":2}"#)
                .unwrap()
                .min_master_password_score,
            2
        );
        // A level this version doesn't know is the strictest, not none.
        assert_eq!(
            policy_parse(r#"{"master_password_min_strength":"extreme"}"#)
                .unwrap()
                .min_master_password_score,
            4
        );
        assert!(policy_parse("[]").is_err());
        assert!(policy_parse(r#"{"export_allowed":"no"}"#).is_err());
    }

    #[test]
    fn violations_name_each_broken_rule() {
        let p = policy_parse(
            r#"{"master_password_min_strength":"good","max_auto_lock_minutes":5,"require_two_step":true}"#,
        )
        .unwrap();
        let ok = LocalSecurity {
            master_password_score: Some(4),
            auto_lock_secs: Some(300),
            two_step_enabled: true,
        };
        assert!(policy_violations(p.clone(), ok.clone()).is_empty());
        let bad = LocalSecurity {
            master_password_score: Some(1),
            auto_lock_secs: None,
            two_step_enabled: false,
        };
        let rules: Vec<PolicyRule> = policy_violations(p.clone(), bad)
            .into_iter()
            .map(|v| v.rule)
            .collect();
        assert_eq!(
            rules,
            [
                PolicyRule::MasterPasswordStrength,
                PolicyRule::AutoLock,
                PolicyRule::TwoStep
            ]
        );
        // An unknown strength is no violation yet.
        let unknown = LocalSecurity {
            master_password_score: None,
            ..ok
        };
        assert!(policy_violations(p.clone(), unknown).is_empty());
        assert!(policy_check_master_password(p.clone(), "abc".into()).is_some());
        assert!(
            policy_check_master_password(p.clone(), "plinth-quarry-velvet-otter-9".into())
                .is_none()
        );
        assert_eq!(policy_auto_lock_secs(p.clone(), Some(3600)), Some(300));
        assert_eq!(policy_auto_lock_secs(p.clone(), None), Some(300));
        assert_eq!(policy_auto_lock_secs(p, Some(60)), Some(60));
    }

    #[test]
    fn export_and_outside_sharing_follow_the_strictest_policy() {
        let team = policy_parse(r#"{"sharing_outside_allowed":false,"max_auto_lock_minutes":30}"#)
            .unwrap();
        let family =
            policy_parse(r#"{"export_allowed":false,"max_auto_lock_minutes":10}"#).unwrap();
        let both = policy_strictest(vec![team.clone(), family]);
        assert!(!both.export_allowed && !both.sharing_outside_allowed);
        assert_eq!(both.max_auto_lock_secs, Some(600));
        assert!(policy_allows_export(None));
        assert!(policy_allows_export(Some(team.clone())));
        assert!(!policy_allows_export(Some(both)));
        // Direct shares: within the org always, outside only if the policy allows it.
        assert!(policy_allows_share(Some(team.clone()), true));
        assert!(!policy_allows_share(Some(team), false));
        assert!(policy_allows_share(None, false));
        assert!(policy_allows_share(Some(OrgPolicy::default()), false));
        assert!(!policy_blocked_message(PolicyBlock::Export).is_empty());
    }
}
