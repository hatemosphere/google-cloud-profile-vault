use std::fmt;
use std::sync::LazyLock;

static ENABLED: LazyLock<bool> = LazyLock::new(|| {
    std::env::var("GCPV_LOG").is_ok_and(|value| value.eq_ignore_ascii_case("debug"))
});

pub fn log(message: fmt::Arguments<'_>) {
    if *ENABLED {
        eprintln!("gcpv: debug: {message}");
    }
}

macro_rules! debug {
    ($($arg:tt)*) => {
        $crate::diagnostics::log(format_args!($($arg)*))
    };
}
pub(crate) use debug;
