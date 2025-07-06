pub const FT4_LOGGING_PREFIX: &str = "FT4 :";

#[macro_export]
macro_rules! ft4_log {
    ($level:ident, $($arg:tt)*) => {
        tracing::$level!("{} {}", $crate::ft4::logging::FT4_LOGGING_PREFIX, format!($($arg)*))
    };
}
