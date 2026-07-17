use std::fmt;

pub fn debug(message: fmt::Arguments<'_>) {
    if std::env::var("GCPV_LOG").is_ok_and(|value| value.eq_ignore_ascii_case("debug")) {
        eprintln!("gcpv: debug: {message}");
    }
}
