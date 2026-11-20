use serde::{Serialize, de::DeserializeOwned};
use serde_json::Value;

use crate::error::{AppError, Result};

/// Deserialize request payload into a typed request.
///
/// Failures are reported the way the Cognito front end reports them:
/// a missing or null required member is a validation error
/// (`InvalidParameterException`), a member of the wrong JSON type is a
/// `SerializationException`.
pub fn parse_request<T: DeserializeOwned>(body: Value) -> Result<T> {
    serde_json::from_value(body).map_err(|e| request_error(&e.to_string()))
}

fn request_error(message: &str) -> AppError {
    if let Some(field) = between(message, "missing field `", "`") {
        return AppError::InvalidParameter(format!(
            "1 validation error detected: Value null at '{}' failed to satisfy constraint: Member must not be null",
            member_name(field)
        ));
    }

    if let Some(value) = between(message, "unknown variant `", "`") {
        let allowed = message
            .split_once("expected ")
            .map(|(_, rest)| {
                rest.trim_start_matches("one of ")
                    .split(", ")
                    .map(|variant| variant.trim_matches('`'))
                    .collect::<Vec<_>>()
                    .join(", ")
            })
            .unwrap_or_default();
        return AppError::InvalidParameter(format!(
            "1 validation error detected: Value '{value}' failed to satisfy constraint: Member must satisfy enum value set: [{allowed}]"
        ));
    }

    if message.starts_with("invalid type: null") {
        return AppError::InvalidParameter(
            "1 validation error detected: Value null failed to satisfy constraint: Member must not be null"
                .to_string(),
        );
    }

    if let Some(found) = message.strip_prefix("invalid type: ") {
        let found = found.split(',').next().unwrap_or(found);
        let json_type = match found.split_whitespace().next().unwrap_or_default() {
            "string" => "STRING_VALUE",
            "integer" | "floating" => "NUMBER_VALUE",
            "boolean" => "TRUE_VALUE",
            "sequence" => "START_ARRAY",
            "map" => "START_OBJECT",
            _ => "VALUE",
        };
        let expected = message
            .split_once("expected ")
            .map(|(_, expected)| expected)
            .unwrap_or("another type");
        return AppError::Serialization(format!("{json_type} can not be converted to {expected}"));
    }

    // Constraint violations raised by the domain types already carry
    // Cognito's wording.
    AppError::InvalidParameter(message.to_string())
}

fn between<'a>(message: &'a str, start: &str, end: &str) -> Option<&'a str> {
    let rest = message.split_once(start)?.1;
    Some(rest.split_once(end)?.0)
}

/// Cognito names members in validation messages in lower camel case
/// (`UserPoolId` is reported as `userPoolId`).
fn member_name(field: &str) -> String {
    let mut chars = field.chars();
    match chars.next() {
        Some(first) => first.to_lowercase().chain(chars).collect(),
        None => String::new(),
    }
}

/// Serialize typed response into Cognito JSON payload.
pub fn to_response_value<T: Serialize>(response: T) -> Result<Value> {
    serde_json::to_value(response).map_err(|e| AppError::Internal(format!("Invalid response: {e}")))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::types::UserPoolId;
    use serde::Deserialize;
    use serde_json::json;

    #[derive(Debug, Deserialize)]
    #[serde(rename_all = "PascalCase")]
    struct Request {
        #[allow(dead_code)]
        user_pool_id: UserPoolId,
        #[allow(dead_code)]
        limit: Option<i32>,
    }

    #[test]
    fn missing_member_is_a_validation_error() {
        let err = parse_request::<Request>(json!({})).unwrap_err();
        assert!(matches!(
            err,
            AppError::InvalidParameter(message)
                if message == "1 validation error detected: Value null at 'userPoolId' failed to satisfy constraint: Member must not be null"
        ));
    }

    #[test]
    fn wrong_json_type_is_a_serialization_error() {
        let err = parse_request::<Request>(json!({"UserPoolId": "us-east-1_abc", "Limit": "x"}))
            .unwrap_err();
        assert!(matches!(
            err,
            AppError::Serialization(message) if message.starts_with("STRING_VALUE can not be converted to")
        ));
    }

    #[test]
    fn pattern_violation_names_the_member() {
        let err = parse_request::<Request>(json!({"UserPoolId": "nope"})).unwrap_err();
        assert!(matches!(
            err,
            AppError::InvalidParameter(message)
                if message == "1 validation error detected: Value 'nope' at 'userPoolId' failed to satisfy constraint: Member must satisfy regular expression pattern: [\\w-]+_[0-9a-zA-Z]+"
        ));
    }
}
