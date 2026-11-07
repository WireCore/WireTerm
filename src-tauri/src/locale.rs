//! The language of the messages that reach the UI.
//!
//! The UI decides (system language or the user's choice) and tells this side
//! through [`set_locale`]. Everything that builds a message for the UI goes
//! through `t!` with a key from `locales/*.yml`; English is the fallback for a
//! key that lacks a translation.

/// The locales the UI offers. Anything else is treated as English.
pub const LOCALES: [&str; 2] = ["en", "de"];

/// The active locale, as sent to the backend in `Accept-Language`.
pub fn current() -> String {
    rust_i18n::locale().to_string()
}

/// Maps `de`, `de-DE` or `DE_at` to a supported locale, anything else to `en`.
pub fn normalize(value: &str) -> &'static str {
    let primary = value.trim().to_lowercase();
    let primary = primary.split(['-', '_']).next().unwrap_or("");
    LOCALES
        .iter()
        .copied()
        .find(|locale| *locale == primary)
        .unwrap_or("en")
}

#[tauri::command]
pub fn set_locale(locale: String) {
    rust_i18n::set_locale(normalize(&locale));
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn regional_variants_map_to_the_supported_locale() {
        assert_eq!(normalize("de-DE"), "de");
        assert_eq!(normalize("DE_at"), "de");
        assert_eq!(normalize("en-US"), "en");
        assert_eq!(normalize("fr"), "en");
        assert_eq!(normalize(""), "en");
    }

    #[test]
    fn messages_exist_in_both_languages() {
        // Asked per call: `set_locale` is global and tests run in parallel.
        let en = rust_i18n::t!("cloud.code_rl", locale = "en");
        let de = rust_i18n::t!("cloud.code_rl", locale = "de");
        assert!(en.contains("requests"), "{en}");
        assert!(de.contains("Anfragen"), "{de}");
        assert_eq!(rust_i18n::available_locales!(), vec!["de", "en"]);
    }
}
