use std::process::Command;

#[test]
fn request_spec_drift_matches_baseline() {
    let manifest_dir = env!("CARGO_MANIFEST_DIR");
    let coverage_path = format!("{manifest_dir}/COVERAGE.md");
    let expected_path = format!("{manifest_dir}/spec/request_field_expected.json");
    let baseline_path = format!("{manifest_dir}/spec/request_field_baseline.json");

    let output = Command::new(env!("CARGO_BIN_EXE_request_response_spec_diff"))
        .args([
            "--coverage-path",
            &coverage_path,
            "--expected-path",
            &expected_path,
            "--baseline-path",
            &baseline_path,
        ])
        .output()
        .expect("failed to run request_response_spec_diff");

    assert!(
        output.status.success(),
        "request_response_spec_diff failed.\nstdout:\n{}\nstderr:\n{}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
}
