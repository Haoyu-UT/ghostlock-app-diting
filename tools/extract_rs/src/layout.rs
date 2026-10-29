//! Stage-2 layout facts: the three groups that already bit us, derived from
//! image BTF with the release template as the labelled fallback.
//!
//! - `rt_mutex_size` — the anchor pitch.
//! - `waiter_layout` — compact vs non-compact `rt_mutex_waiter`, its field
//!   offsets and whether `wake_state` exists.
//! - `cred` layout — `usage` width, `uid`, `security`, the capability run and
//!   the prefix copy size.
//!
//! Nothing here changes what the profile emits. The facts feed `--explain`, and
//! disagreements with the hardcoded 6.x template are logged as warnings — the
//! vendor-backport signal the model was built for.

use crate::btf::Btf;
use crate::fact::{Confidence, Domain, Fact, FactTable, Source};
use crate::family;

#[derive(Debug, Clone)]
pub struct LayoutFacts {
    pub rt_mutex_size: Fact<u32>,
    pub waiter_compact: Fact<bool>,
    pub waiter_pi_tree: Fact<String>,
    pub waiter_task: Fact<String>,
    pub waiter_lock: Fact<String>,
    pub waiter_wake_state: Fact<String>,
    pub cred_usage_size: Fact<String>,
    pub cred_uid_offset: Fact<String>,
    pub cred_security_offset: Fact<String>,
    pub cred_caps_offset: Fact<String>,
    pub cred_copy_size: Fact<String>,
}

impl LayoutFacts {
    pub fn push_rows(&self, table: &mut FactTable) {
        push_copy(table, "layout.rt_mutex_size", &self.rt_mutex_size);
        push_copy(table, "layout.waiter_compact", &self.waiter_compact);
        push_string(table, "layout.waiter_pi_tree", &self.waiter_pi_tree);
        push_string(table, "layout.waiter_task", &self.waiter_task);
        push_string(table, "layout.waiter_lock", &self.waiter_lock);
        push_string(table, "layout.waiter_wake_state", &self.waiter_wake_state);
        push_string(table, "layout.cred_usage_size", &self.cred_usage_size);
        push_string(table, "layout.cred_uid_offset", &self.cred_uid_offset);
        push_string(table, "layout.cred_security_offset", &self.cred_security_offset);
        push_string(table, "layout.cred_caps_offset", &self.cred_caps_offset);
        push_string(table, "layout.cred_copy_size", &self.cred_copy_size);
    }
}

fn push_copy<T: std::fmt::Display + Copy>(table: &mut FactTable, key: &str, fact: &Fact<T>) {
    table.push(
        key,
        Fact::new(fact.value, fact.domain, fact.source, fact.confidence),
    );
}

fn push_string(table: &mut FactTable, key: &str, fact: &Fact<String>) {
    table.push(
        key,
        Fact::new(fact.value.clone(), fact.domain, fact.source, fact.confidence),
    );
}

fn btf_fact<T>(value: T, domain: Domain) -> Fact<T> {
    Fact::new(value, domain, Source::Btf, Confidence::Derived)
}

fn template_fact<T>(value: T, domain: Domain) -> Fact<T> {
    Fact::new(value, domain, Source::ReleaseTemplate, Confidence::Heuristic)
}

fn unknown_fact(domain: Domain) -> Fact<String> {
    Fact::new(
        "null".to_string(),
        domain,
        Source::Unknown,
        Confidence::Unknown,
    )
}

fn hex_or_null(value: Option<u32>) -> String {
    value
        .map(|value| format!("0x{value:x}"))
        .unwrap_or_else(|| "null".to_string())
}

fn btf_or_unknown(value: Option<u32>, domain: Domain) -> Fact<String> {
    match value {
        Some(value) => btf_fact(format!("0x{value:x}"), domain),
        None => unknown_fact(domain),
    }
}

fn dec_or_null(value: Option<u32>) -> String {
    value
        .map(|value| value.to_string())
        .unwrap_or_else(|| "null".to_string())
}

/// Derives the three layout groups. BTF is primary; the release template fills
/// only what BTF cannot supply, and the fact keeps that label.
pub fn derive(btf: Option<&Btf>, release: &str) -> LayoutFacts {
    let family_compact = family::is_compact_waiter_family(release);
    let btf_compact = btf.and_then(|btf| {
        btf.named_struct("rt_mutex_waiter")
            .map(|_| btf.field("rt_mutex_waiter", "prio").is_some())
    });
    if let Some(compact) = btf_compact {
        if compact != family_compact {
            eprintln!(
                "warning: BTF says the rt_mutex_waiter is {}; the release predicate says {}",
                if compact { "compact" } else { "non-compact" },
                if family_compact { "compact" } else { "non-compact" }
            );
        }
    }
    let waiter_compact = match btf_compact {
        Some(compact) => btf_fact(compact, Domain::EnumValue),
        None => template_fact(family_compact, Domain::EnumValue),
    };

    let rt_mutex_size = match btf.and_then(|btf| btf.size("rt_mutex")) {
        Some(size) => {
            if size != family::ANCHOR_STRIDE as u32 {
                eprintln!(
                    "warning: BTF sizeof(rt_mutex) = {size}; the family constant is {}",
                    family::ANCHOR_STRIDE
                );
            }
            btf_fact(size, Domain::SizeOf)
        }
        None => template_fact(family::ANCHOR_STRIDE as u32, Domain::SizeOf),
    };

    let btf_waiter = btf.map(|btf| {
        (
            btf.field("rt_mutex_waiter", "pi_tree")
                .or_else(|| btf.field("rt_mutex_waiter", "pi_tree_entry")),
            btf.field("rt_mutex_waiter", "task"),
            btf.field("rt_mutex_waiter", "lock"),
            btf.field("rt_mutex_waiter", "wake_state"),
        )
    });
    let (pi_tree, task, lock, wake_state) = match btf_waiter {
        Some(fields) => fields,
        None if family::matches(release) => {
            let layout = family::waiter_layout_5_10();
            (
                Some(layout.pi_tree_entry as u32),
                layout.task.map(|value| value as u32),
                layout.lock.map(|value| value as u32),
                layout.wake_state.map(|value| value as u32),
            )
        }
        None => (None, None, None, None),
    };
    let (pi_tree_fact, task_fact, lock_fact, wake_fact) = match btf {
        Some(_) => (
            btf_or_unknown(pi_tree, Domain::FieldOffset),
            btf_or_unknown(task, Domain::FieldOffset),
            btf_or_unknown(lock, Domain::FieldOffset),
            btf_or_unknown(wake_state, Domain::FieldOffset),
        ),
        None if family::matches(release) => (
            template_fact(hex_or_null(pi_tree), Domain::FieldOffset),
            template_fact(hex_or_null(task), Domain::FieldOffset),
            template_fact(hex_or_null(lock), Domain::FieldOffset),
            template_fact(hex_or_null(wake_state), Domain::FieldOffset),
        ),
        None => (
            unknown_fact(Domain::FieldOffset),
            unknown_fact(Domain::FieldOffset),
            unknown_fact(Domain::FieldOffset),
            unknown_fact(Domain::FieldOffset),
        ),
    };

    let major = release
        .split('.')
        .next()
        .and_then(|part| part.parse::<u32>().ok());
    let usage_size = btf.and_then(|btf| btf.direct_field_size("cred", "usage"));
    let uid = btf.and_then(|btf| btf.field("cred", "uid"));
    let security = btf.and_then(|btf| btf.field("cred", "security"));
    let caps = btf.and_then(|btf| btf.field("cred", "cap_inheritable"));
    // The 6.x template's copy length is the span through `security`; this is a
    // minimum, not sizeof(cred) (5.x carries pointers and an rcu head after
    // `security`, and uses sizeof from BTF on its own path).
    let copy_size = security.map(|offset| offset + 8);

    // The hardcoded 6.x template: usage/uid 4 bytes, security at +128 (copy
    // 136), the capability run at +48. It matches 6.6/6.12 and not 6.1; the
    // warnings below are how that becomes visible.
    let template = (major == Some(6)).then_some((4u32, 4u32, 128u32, 48u32, 136u32));
    if let (Some(size), Some(uid_offset), Some(security_offset), Some(caps_offset), Some(copy)) =
        (usage_size, uid, security, caps, copy_size)
    {
        if let Some((t_usage, t_uid, t_security, t_caps, t_copy)) = template {
            if size != t_usage {
                eprintln!(
                    "warning: BTF cred.usage is {size} bytes; the 6.x template assumes {t_usage}"
                );
            }
            if uid_offset != t_uid {
                eprintln!(
                    "warning: BTF cred.uid is at +{uid_offset}; the 6.x template assumes +{t_uid}"
                );
            }
            if copy != t_copy || security_offset != t_security {
                eprintln!(
                    "warning: BTF cred.security is +{security_offset} (copy {copy}); the 6.x template uses +{t_security}/{t_copy}"
                );
            }
            if caps_offset != t_caps {
                eprintln!(
                    "warning: BTF cred cap_inheritable is +{caps_offset}; the 6.x template uses +{t_caps}"
                );
            }
        }
    }

    let usage_fact = match usage_size {
        Some(value) => btf_fact(dec_or_null(Some(value)), Domain::SizeOf),
        None => template
            .map(|(usage, _, _, _, _)| template_fact(usage.to_string(), Domain::SizeOf))
            .unwrap_or_else(|| unknown_fact(Domain::SizeOf)),
    };
    let uid_fact = match uid {
        Some(value) => btf_fact(dec_or_null(Some(value)), Domain::FieldOffset),
        None => template
            .map(|(_, uid, _, _, _)| template_fact(uid.to_string(), Domain::FieldOffset))
            .unwrap_or_else(|| unknown_fact(Domain::FieldOffset)),
    };
    let security_fact = match security {
        Some(value) => btf_fact(dec_or_null(Some(value)), Domain::FieldOffset),
        None => template
            .map(|(_, _, security, _, _)| template_fact(security.to_string(), Domain::FieldOffset))
            .unwrap_or_else(|| unknown_fact(Domain::FieldOffset)),
    };
    let caps_fact = match caps {
        Some(value) => btf_fact(dec_or_null(Some(value)), Domain::FieldOffset),
        None => template
            .map(|(_, _, _, caps, _)| template_fact(caps.to_string(), Domain::FieldOffset))
            .unwrap_or_else(|| unknown_fact(Domain::FieldOffset)),
    };
    let copy_fact = match copy_size {
        Some(value) => btf_fact(dec_or_null(Some(value)), Domain::SizeOf),
        None => template
            .map(|(_, _, _, _, copy)| template_fact(copy.to_string(), Domain::SizeOf))
            .unwrap_or_else(|| unknown_fact(Domain::SizeOf)),
    };

    LayoutFacts {
        rt_mutex_size,
        waiter_compact,
        waiter_pi_tree: pi_tree_fact,
        waiter_task: task_fact,
        waiter_lock: lock_fact,
        waiter_wake_state: wake_fact,
        cred_usage_size: usage_fact,
        cred_uid_offset: uid_fact,
        cred_security_offset: security_fact,
        cred_caps_offset: caps_fact,
        cred_copy_size: copy_fact,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn no_btf_5_10_uses_the_family_waiter_and_pitch() {
        let facts = derive(None, "5.10.236-android12-9-00003-gfb24cf99ad97");
        assert_eq!(facts.rt_mutex_size.value, 32);
        assert_eq!(facts.rt_mutex_size.source, Source::ReleaseTemplate);
        assert!(facts.waiter_compact.value);
        assert_eq!(facts.waiter_compact.source, Source::ReleaseTemplate);
        assert_eq!(facts.waiter_pi_tree.value, "0x18");
        assert_eq!(facts.waiter_task.value, "0x30");
        // No BTF and no built-in cred block: the facts stay unknown.
        assert_eq!(facts.cred_usage_size.value, "null");
        assert_eq!(facts.cred_usage_size.source, Source::Unknown);
    }

    #[test]
    fn no_btf_6x_uses_the_labelled_template() {
        let facts = derive(None, "6.6.66-android15-8-g29d86c5fc9dd");
        assert!(!facts.waiter_compact.value);
        assert_eq!(facts.waiter_compact.source, Source::ReleaseTemplate);
        assert_eq!(facts.cred_usage_size.value, "4");
        assert_eq!(facts.cred_usage_size.source, Source::ReleaseTemplate);
        assert_eq!(facts.cred_uid_offset.value, "4");
        assert_eq!(facts.cred_security_offset.value, "128");
        assert_eq!(facts.cred_caps_offset.value, "48");
        assert_eq!(facts.cred_copy_size.value, "136");
    }
}
