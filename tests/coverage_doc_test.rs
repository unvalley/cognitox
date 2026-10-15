//! Keeps COVERAGE.md and the coverage numbers quoted elsewhere in sync with
//! the action registry in `src/api/cognito_idp.rs`.

use std::collections::BTreeSet;
use std::fs;
use std::path::Path;

use cognitox::api::cognito_idp::Action;

struct Row {
    operation: String,
    aligned: bool,
    handler_path: String,
}

fn read(relative: &str) -> String {
    let path = Path::new(env!("CARGO_MANIFEST_DIR")).join(relative);
    fs::read_to_string(&path).unwrap_or_else(|e| panic!("failed to read {relative}: {e}"))
}

fn coverage_rows() -> Vec<Row> {
    read("COVERAGE.md")
        .lines()
        .filter_map(|line| {
            let (aligned, rest) = match line.strip_prefix("- [x] ") {
                Some(rest) => (true, rest),
                None => (false, line.strip_prefix("- [ ] ")?),
            };
            let operation = rest.split_whitespace().next()?.to_string();
            let handler_path = rest
                .split_once("[cognitox](")
                .and_then(|(_, tail)| tail.split_once(')'))
                .map(|(path, _)| path.to_string())
                .unwrap_or_else(|| panic!("COVERAGE.md row for {operation} has no handler link"));
            Some(Row {
                operation,
                aligned,
                handler_path,
            })
        })
        .collect()
}

#[test]
fn coverage_lists_every_registered_action_once() {
    let rows = coverage_rows();

    let mut listed = BTreeSet::new();
    for row in &rows {
        assert!(
            row.operation.parse::<Action>().is_ok(),
            "COVERAGE.md lists {}, which is not in the action registry",
            row.operation
        );
        assert!(
            listed.insert(row.operation.as_str()),
            "COVERAGE.md lists {} more than once",
            row.operation
        );
    }

    let registered: Vec<String> = Action::ALL.iter().map(|a| format!("{a:?}")).collect();
    let missing: Vec<&String> = registered
        .iter()
        .filter(|name| !listed.contains(name.as_str()))
        .collect();
    assert!(
        missing.is_empty(),
        "registered actions missing from COVERAGE.md: {missing:?}"
    );
}

#[test]
fn coverage_handler_links_exist() {
    let root = Path::new(env!("CARGO_MANIFEST_DIR"));
    for row in coverage_rows() {
        assert!(
            root.join(&row.handler_path).is_file(),
            "COVERAGE.md links {} to {}, which does not exist",
            row.operation,
            row.handler_path
        );
    }
}

#[test]
fn coverage_summary_numbers_match_checklist() {
    let rows = coverage_rows();
    let total = rows.len();
    let aligned = rows.iter().filter(|row| row.aligned).count();
    let percent = (aligned * 100 + total / 2) / total;

    let expectations = [
        (
            "COVERAGE.md",
            format!("All {total} Cognito IDP operations are routed"),
        ),
        (
            "COVERAGE.md",
            format!("{percent}% spec-aligned ({aligned}/{total})"),
        ),
        (
            "README.md",
            format!(
                "routes all {total} cognito-idp operations, with **{aligned} ({percent}%) currently spec-aligned**. The remaining {}",
                total - aligned
            ),
        ),
        (
            "src/main.rs",
            format!("Implements all {total} cognito-idp API operations"),
        ),
    ];

    for (file, expected) in expectations {
        assert!(
            read(file).contains(&expected),
            "{file} does not match the COVERAGE.md checklist ({aligned}/{total} spec-aligned); expected it to contain:\n  {expected}"
        );
    }
}
