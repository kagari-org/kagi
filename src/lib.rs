pub(crate) mod audit;
pub mod config;
pub(crate) mod input;
pub mod policy;
pub(crate) mod registry;
pub mod server;
pub(crate) mod stream;
pub(crate) mod tui;

pub(crate) fn format_hms(duration: std::time::Duration) -> String {
    let secs = duration.as_secs();
    format!(
        "{:02}:{:02}:{:02}",
        secs / 3600,
        (secs % 3600) / 60,
        secs % 60
    )
}

#[cfg(test)]
mod tests {
    use super::format_hms;
    use std::time::Duration;

    #[test]
    fn formats_duration_as_hms() {
        assert_eq!(format_hms(Duration::ZERO), "00:00:00");
        assert_eq!(format_hms(Duration::from_secs(59)), "00:00:59");
        assert_eq!(format_hms(Duration::from_secs(3661)), "01:01:01");
    }
}
