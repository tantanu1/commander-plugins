//! Host-safety name rules shared by the host and plugins.

/// Windows reserved device name (`CON`, `nul.txt`, `COM1 .log`, `LPT¹`, `CONIN$`...): opening
/// it writes to the device, not a file.
pub fn is_device_name(part: &str) -> bool {
    let stem = part.split('.').next().unwrap_or("").trim_end_matches(' ');
    let up = stem.to_ascii_uppercase();
    let numbered = up.split_at_checked(3).is_some_and(|(p, n)| {
        matches!(p, "COM" | "LPT")
            && (matches!(n.as_bytes(), [b'1'..=b'9']) || matches!(n, "¹" | "²" | "³"))
    });
    numbered
        || matches!(
            up.as_str(),
            "CON" | "PRN" | "AUX" | "NUL" | "CONIN$" | "CONOUT$"
        )
}
