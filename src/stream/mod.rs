use anyhow::{Result, bail};

use crate::policy::Subject;

pub mod attach;

pub fn owner_for(subject: &Subject, session_id: u64) -> String {
    if subject.as_str() == "anonymous" {
        format!("anonymous#{session_id}")
    } else {
        subject.label()
    }
}

pub fn normalize_name(raw: Option<&str>, session_id: u64) -> Result<String> {
    match raw {
        None | Some("") => Ok(format!("s{session_id}")),
        Some(name) => {
            let name = name.trim();
            if name.is_empty() {
                return Ok(format!("s{session_id}"));
            }
            if name.len() > 32 {
                bail!("stream name is longer than 32 characters");
            }
            if !name
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '_' | '-'))
            {
                bail!("stream name may only contain ASCII letters, digits, '.', '_' and '-'");
            }
            Ok(name.to_string())
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn defaults_to_session_name() {
        assert_eq!(normalize_name(None, 7).unwrap(), "s7");
        assert_eq!(normalize_name(Some(""), 7).unwrap(), "s7");
    }

    #[test]
    fn rejects_bad_names() {
        assert!(normalize_name(Some("a/b"), 7).is_err());
        assert!(normalize_name(Some("a b"), 7).is_err());
        assert!(normalize_name(Some(&"a".repeat(33)), 7).is_err());
    }
}
