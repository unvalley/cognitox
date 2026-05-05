use std::{
    collections::{BTreeMap, BTreeSet},
    env, fs,
    path::{Path, PathBuf},
    process::ExitCode,
};

use serde::{Deserialize, Serialize};

#[derive(Debug)]
struct Config {
    coverage_path: PathBuf,
    expected_path: PathBuf,
    baseline_path: PathBuf,
    update_baseline: bool,
    strict: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExpectedOperation {
    request: Vec<String>,
    response: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct ExpectedSpec {
    model_url: String,
    model_sha256: String,
    operations: BTreeMap<String, ExpectedOperation>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct FieldDiff {
    missing: Vec<String>,
    extra: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
struct OperationDiff {
    path: String,
    request: FieldDiff,
    response: FieldDiff,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
struct DriftReport {
    model_url: String,
    model_sha256: String,
    operations: BTreeMap<String, OperationDiff>,
}

fn normalize_key(input: &str) -> String {
    input
        .chars()
        .filter(|c| c.is_ascii_alphanumeric())
        .flat_map(char::to_lowercase)
        .collect()
}

fn parse_args() -> Result<Config, String> {
    let mut config = Config {
        coverage_path: PathBuf::from("COVERAGE.md"),
        expected_path: PathBuf::from("spec/request_field_expected.json"),
        baseline_path: PathBuf::from("spec/request_field_baseline.json"),
        update_baseline: false,
        strict: false,
    };

    let args: Vec<String> = env::args().skip(1).collect();
    let mut i = 0usize;
    while i < args.len() {
        match args[i].as_str() {
            "--coverage-path" => {
                i += 1;
                let Some(value) = args.get(i) else {
                    return Err("--coverage-path requires a value".to_string());
                };
                config.coverage_path = PathBuf::from(value);
            }
            "--expected-path" => {
                i += 1;
                let Some(value) = args.get(i) else {
                    return Err("--expected-path requires a value".to_string());
                };
                config.expected_path = PathBuf::from(value);
            }
            "--baseline-path" => {
                i += 1;
                let Some(value) = args.get(i) else {
                    return Err("--baseline-path requires a value".to_string());
                };
                config.baseline_path = PathBuf::from(value);
            }
            "--update-baseline" => {
                config.update_baseline = true;
            }
            "--strict" => {
                config.strict = true;
            }
            "--help" | "-h" => {
                return Err(
                    "usage: cargo run --bin request_response_spec_diff -- [--strict] [--update-baseline] [--coverage-path PATH] [--expected-path PATH] [--baseline-path PATH]"
                        .to_string(),
                );
            }
            other => {
                return Err(format!("unknown argument: {other}"));
            }
        }
        i += 1;
    }

    Ok(config)
}

fn load_coverage_mapping(path: &Path) -> Result<Vec<(String, String)>, String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    let mut rows = Vec::new();

    for line in content.lines() {
        if !line.starts_with("- [x] ") {
            continue;
        }
        let rest = &line[6..];
        let Some(operation) = rest.split_whitespace().next() else {
            continue;
        };
        let Some(path_start) = line.find("[cognitox](") else {
            continue;
        };
        let path_start = path_start + "[cognitox](".len();
        let Some(path_end_rel) = line[path_start..].find(')') else {
            continue;
        };
        let operation_path = &line[path_start..path_start + path_end_rel];
        rows.push((operation.to_string(), operation_path.to_string()));
    }

    if rows.is_empty() {
        return Err(format!("no operation rows found in {}", path.display()));
    }

    Ok(rows)
}

fn extract_struct_fields(path: &Path, struct_name: &str) -> Result<Option<Vec<String>>, String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    let lines: Vec<&str> = content.lines().collect();

    let marker = format!("struct {struct_name}");
    let Some(start_index) = lines
        .iter()
        .position(|line| line.contains(&marker) && line.contains('{'))
    else {
        return Ok(None);
    };

    let mut fields = Vec::new();
    for line in lines.into_iter().skip(start_index + 1) {
        let trimmed = line.trim();
        if trimmed.starts_with('}') {
            break;
        }
        if trimmed.is_empty() || trimmed.starts_with("//") || trimmed.starts_with("#[") {
            continue;
        }
        if !trimmed.ends_with(',') {
            continue;
        }

        let Some((left, _)) = trimmed.split_once(':') else {
            continue;
        };
        let candidate = left.trim().trim_start_matches("pub ").trim();
        if candidate
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || c == '_')
        {
            fields.push(candidate.to_string());
        }
    }

    Ok(Some(fields))
}

fn brace_delta(line: &str) -> i32 {
    line.chars().fold(0i32, |acc, c| match c {
        '{' => acc + 1,
        '}' => acc - 1,
        _ => acc,
    })
}

fn parse_top_level_json_object_keys(object_lines: &[String]) -> Vec<String> {
    let mut depth = 0i32;
    let mut keys = Vec::new();

    for line in object_lines {
        let trimmed = line.trim_start();
        if depth == 1 && trimmed.starts_with('"') {
            let rest = &trimmed[1..];
            if let Some(end_quote) = rest.find('"') {
                let key = &rest[..end_quote];
                let after_quote = &rest[end_quote + 1..];
                if after_quote.trim_start().starts_with(':') {
                    keys.push(key.to_string());
                }
            }
        }
        depth += brace_delta(line);
    }

    keys.sort();
    keys.dedup();
    keys
}

fn collect_json_object_after_marker(lines: &[&str], marker: &str) -> Option<Vec<String>> {
    let mut object_lines = Vec::new();
    let mut collecting = false;
    let mut depth = 0i32;

    for line in lines {
        if !collecting {
            let Some(marker_pos) = line.find(marker) else {
                continue;
            };
            let remain = &line[marker_pos + marker.len()..];
            let Some(obj_start) = remain.find('{') else {
                continue;
            };

            let fragment = &remain[obj_start..];
            object_lines.push(fragment.to_string());
            depth += brace_delta(fragment);
            collecting = true;
            if depth <= 0 {
                break;
            }
            continue;
        }

        object_lines.push((*line).to_string());
        depth += brace_delta(line);
        if depth <= 0 {
            break;
        }
    }

    (!object_lines.is_empty()).then_some(object_lines)
}

fn collect_response_index_keys(lines: &[&str]) -> Vec<String> {
    let mut keys = Vec::new();

    for line in lines {
        let trimmed = line.trim_start();
        let Some(rest) = trimmed.strip_prefix("response[\"") else {
            continue;
        };
        let Some(end_quote) = rest.find('"') else {
            continue;
        };
        let key = &rest[..end_quote];
        let after_quote = &rest[end_quote + 1..];
        if after_quote.trim_start().starts_with(']') {
            keys.push(key.to_string());
        }
    }

    keys
}

fn extract_json_response_fields(path: &Path) -> Result<Option<Vec<String>>, String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    let lines: Vec<&str> = content.lines().collect();

    if let Some(object_lines) = collect_json_object_after_marker(&lines, "Ok(json!(") {
        return Ok(Some(parse_top_level_json_object_keys(&object_lines)));
    }

    if let Some(object_lines) =
        collect_json_object_after_marker(&lines, "let mut response = json!(")
    {
        let mut keys = parse_top_level_json_object_keys(&object_lines);
        keys.extend(collect_response_index_keys(&lines));
        keys.sort();
        keys.dedup();
        return Ok(Some(keys));
    }

    Ok(None)
}

fn extract_response_fields(path: &Path) -> Result<Vec<String>, String> {
    if let Some(fields) = extract_struct_fields(path, "Response")? {
        return Ok(fields);
    }

    if let Some(fields) = extract_json_response_fields(path)? {
        return Ok(fields);
    }

    Ok(Vec::new())
}

fn load_expected(path: &Path) -> Result<ExpectedSpec, String> {
    let content =
        fs::read_to_string(path).map_err(|e| format!("failed to read {}: {e}", path.display()))?;
    serde_json::from_str(&content).map_err(|e| format!("failed to parse {}: {e}", path.display()))
}

fn build_field_diff(expected_fields: &[String], actual_fields: &[String]) -> FieldDiff {
    let expected_by_norm: BTreeMap<String, String> = expected_fields
        .iter()
        .map(|field| (normalize_key(field), field.clone()))
        .collect();
    let actual_by_norm: BTreeMap<String, String> = actual_fields
        .iter()
        .map(|field| (normalize_key(field), field.clone()))
        .collect();

    let expected_keys: BTreeSet<_> = expected_by_norm.keys().cloned().collect();
    let actual_keys: BTreeSet<_> = actual_by_norm.keys().cloned().collect();

    let missing = expected_keys
        .difference(&actual_keys)
        .filter_map(|key| expected_by_norm.get(key).cloned())
        .collect::<Vec<_>>();
    let extra = actual_keys
        .difference(&expected_keys)
        .filter_map(|key| actual_by_norm.get(key).cloned())
        .collect::<Vec<_>>();

    FieldDiff { missing, extra }
}

fn generate_report(
    expected: &ExpectedSpec,
    coverage_rows: &[(String, String)],
) -> Result<DriftReport, String> {
    let mut report = DriftReport {
        model_url: expected.model_url.clone(),
        model_sha256: expected.model_sha256.clone(),
        operations: BTreeMap::new(),
    };

    for (operation_name, operation_path) in coverage_rows {
        let expected_op = expected
            .operations
            .get(operation_name)
            .ok_or_else(|| format!("operation `{operation_name}` not found in expected file"))?;

        let request_fields = extract_struct_fields(Path::new(operation_path), "Request")?
            .ok_or_else(|| format!("`struct Request` not found in {}", operation_path))?;
        let response_fields = extract_response_fields(Path::new(operation_path))?;

        let request = build_field_diff(&expected_op.request, &request_fields);
        let response = build_field_diff(&expected_op.response, &response_fields);

        report.operations.insert(
            operation_name.clone(),
            OperationDiff {
                path: operation_path.clone(),
                request,
                response,
            },
        );
    }

    Ok(report)
}

fn summarize_drift(report: &DriftReport) -> (usize, usize, usize, usize, usize) {
    let mut drift_ops = 0usize;
    let mut req_missing_total = 0usize;
    let mut req_extra_total = 0usize;
    let mut resp_missing_total = 0usize;
    let mut resp_extra_total = 0usize;

    for details in report.operations.values() {
        let has_request_drift =
            !details.request.missing.is_empty() || !details.request.extra.is_empty();
        let has_response_drift =
            !details.response.missing.is_empty() || !details.response.extra.is_empty();
        if has_request_drift || has_response_drift {
            drift_ops += 1;
        }

        req_missing_total += details.request.missing.len();
        req_extra_total += details.request.extra.len();
        resp_missing_total += details.response.missing.len();
        resp_extra_total += details.response.extra.len();
    }

    (
        drift_ops,
        req_missing_total,
        req_extra_total,
        resp_missing_total,
        resp_extra_total,
    )
}

fn compare_with_baseline(report: &DriftReport, baseline_path: &Path) -> Result<(), String> {
    if !baseline_path.exists() {
        return Err(format!(
            "baseline file is missing: {}",
            baseline_path.display()
        ));
    }

    let baseline_raw = fs::read_to_string(baseline_path)
        .map_err(|e| format!("failed to read {}: {e}", baseline_path.display()))?;
    let baseline: DriftReport = serde_json::from_str(&baseline_raw)
        .map_err(|e| format!("invalid baseline JSON {}: {e}", baseline_path.display()))?;

    if baseline.operations == report.operations {
        return Ok(());
    }

    let baseline_keys: BTreeSet<_> = baseline.operations.keys().cloned().collect();
    let current_keys: BTreeSet<_> = report.operations.keys().cloned().collect();

    let absent_in_baseline = current_keys
        .difference(&baseline_keys)
        .cloned()
        .collect::<Vec<_>>();
    let absent_in_current = baseline_keys
        .difference(&current_keys)
        .cloned()
        .collect::<Vec<_>>();

    if !absent_in_baseline.is_empty() {
        eprintln!(
            "operations absent in baseline: {}",
            absent_in_baseline.join(", ")
        );
    }
    if !absent_in_current.is_empty() {
        eprintln!(
            "operations absent in current report: {}",
            absent_in_current.join(", ")
        );
    }

    let mut changed = Vec::new();
    for key in baseline_keys.intersection(&current_keys) {
        let before = &baseline.operations[key];
        let after = &report.operations[key];
        if before != after {
            changed.push(key.clone());
        }
    }

    for op in changed.iter().take(20) {
        let before = &baseline.operations[op];
        let after = &report.operations[op];
        eprintln!(
            concat!(
                "{}: ",
                "baseline request(missing={:?}, extra={:?}) response(missing={:?}, extra={:?}) ",
                "=> current request(missing={:?}, extra={:?}) response(missing={:?}, extra={:?})"
            ),
            op,
            before.request.missing,
            before.request.extra,
            before.response.missing,
            before.response.extra,
            after.request.missing,
            after.request.extra,
            after.response.missing,
            after.response.extra
        );
    }
    if changed.len() > 20 {
        eprintln!("... and {} more changed operations", changed.len() - 20);
    }

    Err("baseline mismatch detected. update after review with:\n  cargo run --bin request_response_spec_diff -- --update-baseline".to_string())
}

fn run(config: Config) -> Result<(), String> {
    let coverage_rows = load_coverage_mapping(&config.coverage_path)?;
    let expected = load_expected(&config.expected_path)?;
    let report = generate_report(&expected, &coverage_rows)?;

    let (drift_ops, req_missing, req_extra, resp_missing, resp_extra) = summarize_drift(&report);
    println!(
        concat!(
            "Request/Response drift summary: operations_with_drift={}, ",
            "request_missing_fields={}, request_extra_fields={}, ",
            "response_missing_fields={}, response_extra_fields={}"
        ),
        drift_ops, req_missing, req_extra, resp_missing, resp_extra
    );

    if config.update_baseline {
        if let Some(parent) = config.baseline_path.parent() {
            fs::create_dir_all(parent)
                .map_err(|e| format!("failed to create {}: {e}", parent.display()))?;
        }
        let json = serde_json::to_string_pretty(&report)
            .map_err(|e| format!("failed to serialize baseline JSON: {e}"))?;
        fs::write(&config.baseline_path, format!("{json}\n"))
            .map_err(|e| format!("failed to write {}: {e}", config.baseline_path.display()))?;
        println!("Updated baseline: {}", config.baseline_path.display());
        return Ok(());
    }

    if config.strict {
        if drift_ops == 0 {
            println!("No drift found.");
            return Ok(());
        }
        eprintln!("Drift detected in strict mode.");
        for (operation, details) in &report.operations {
            let has_request_drift =
                !details.request.missing.is_empty() || !details.request.extra.is_empty();
            let has_response_drift =
                !details.response.missing.is_empty() || !details.response.extra.is_empty();
            if has_request_drift || has_response_drift {
                eprintln!(
                    "- {operation}: request(missing={:?}, extra={:?}) response(missing={:?}, extra={:?}) ({})",
                    details.request.missing,
                    details.request.extra,
                    details.response.missing,
                    details.response.extra,
                    details.path
                );
            }
        }
        return Err("strict mode failed".to_string());
    }

    compare_with_baseline(&report, &config.baseline_path)?;
    println!("Baseline matched: {}", config.baseline_path.display());
    Ok(())
}

fn main() -> ExitCode {
    let config = match parse_args() {
        Ok(config) => config,
        Err(message) => {
            eprintln!("{message}");
            return ExitCode::from(2);
        }
    };

    match run(config) {
        Ok(()) => ExitCode::SUCCESS,
        Err(message) => {
            eprintln!("{message}");
            ExitCode::from(1)
        }
    }
}
