fn main() {
    // The GUI half is optional; only compile the .slint UI when it's enabled.
    if std::env::var_os("CARGO_FEATURE_GUI").is_some() {
        let config = slint_build::CompilerConfiguration::new().with_style("fluent-dark".into());
        slint_build::compile_with_config("ui/guard.slint", config).unwrap();
    }
}
