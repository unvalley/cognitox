//! Paging shared by the list operations.
//!
//! Cognito bounds the page size of every list operation and hands out an
//! opaque `NextToken` while more results remain. The emulator's token is the
//! offset of the next item.

use crate::error::{AppError, Result};

/// One page of a result set of `total` items.
#[derive(Debug, PartialEq, Eq)]
pub(crate) struct Page {
    pub start: usize,
    pub end: usize,
    /// `NextToken`, present while items remain after this page.
    pub next_token: Option<String>,
}

/// Resolve a `MaxResults` / `Limit` member to a page size.
///
/// `member` is the name Cognito uses in validation messages (`maxResults`,
/// `limit`). A value outside `minimum..=maximum` is rejected the way the
/// service front end rejects it; a missing value, or `0` where the operation
/// allows it, means the largest page.
pub(crate) fn page_size(
    value: Option<i32>,
    member: &str,
    minimum: i32,
    maximum: i32,
) -> Result<usize> {
    let Some(value) = value else {
        return Ok(maximum as usize);
    };
    if value < minimum {
        return Err(AppError::InvalidParameter(format!(
            "1 validation error detected: Value '{value}' at '{member}' failed to satisfy constraint: Member must have value greater than or equal to {minimum}"
        )));
    }
    if value > maximum {
        return Err(AppError::InvalidParameter(format!(
            "1 validation error detected: Value '{value}' at '{member}' failed to satisfy constraint: Member must have value less than or equal to {maximum}"
        )));
    }
    Ok(if value == 0 { maximum } else { value } as usize)
}

/// A page size for an operation whose `MaxResults` is required.
pub(crate) fn required_page_size(
    value: Option<i32>,
    member: &str,
    minimum: i32,
    maximum: i32,
) -> Result<usize> {
    if value.is_none() {
        return Err(AppError::InvalidParameter(format!(
            "1 validation error detected: Value null at '{member}' failed to satisfy constraint: Member must not be null"
        )));
    }
    page_size(value, member, minimum, maximum)
}

/// Locate the page a `NextToken` continues from.
pub(crate) fn paginate(total: usize, size: usize, next_token: Option<&str>) -> Result<Page> {
    let invalid_token = || AppError::InvalidParameter("Invalid NextToken".to_string());

    let start = match next_token {
        Some(token) => token.parse::<usize>().map_err(|_| invalid_token())?,
        None => 0,
    };
    if start > total {
        return Err(invalid_token());
    }

    let end = start.saturating_add(size).min(total);
    Ok(Page {
        start,
        end,
        next_token: (end < total).then(|| end.to_string()),
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    fn message(result: Result<usize>) -> String {
        match result {
            Err(AppError::InvalidParameter(message)) => message,
            other => panic!("expected InvalidParameterException, got {other:?}"),
        }
    }

    #[test]
    fn page_size_defaults_to_the_maximum() {
        assert_eq!(page_size(None, "limit", 0, 60).unwrap(), 60);
        assert_eq!(page_size(Some(0), "limit", 0, 60).unwrap(), 60);
        assert_eq!(page_size(Some(25), "limit", 0, 60).unwrap(), 25);
        assert_eq!(page_size(None, "maxResults", 1, 50).unwrap(), 50);
    }

    #[test]
    fn page_size_outside_the_range_is_a_validation_error() {
        assert_eq!(
            message(page_size(Some(61), "maxResults", 1, 60)),
            "1 validation error detected: Value '61' at 'maxResults' failed to satisfy constraint: Member must have value less than or equal to 60"
        );
        assert_eq!(
            message(page_size(Some(0), "maxResults", 1, 60)),
            "1 validation error detected: Value '0' at 'maxResults' failed to satisfy constraint: Member must have value greater than or equal to 1"
        );
        assert_eq!(
            message(page_size(Some(-1), "limit", 0, 60)),
            "1 validation error detected: Value '-1' at 'limit' failed to satisfy constraint: Member must have value greater than or equal to 0"
        );
    }

    #[test]
    fn required_page_size_must_be_present() {
        assert_eq!(
            message(required_page_size(None, "maxResults", 1, 60)),
            "1 validation error detected: Value null at 'maxResults' failed to satisfy constraint: Member must not be null"
        );
        assert_eq!(
            required_page_size(Some(10), "maxResults", 1, 60).unwrap(),
            10
        );
    }

    #[test]
    fn next_token_walks_the_result_set() {
        let first = paginate(5, 2, None).unwrap();
        assert_eq!((first.start, first.end), (0, 2));
        let second = paginate(5, 2, first.next_token.as_deref()).unwrap();
        assert_eq!((second.start, second.end), (2, 4));
        let last = paginate(5, 2, second.next_token.as_deref()).unwrap();
        assert_eq!((last.start, last.end), (4, 5));
        assert_eq!(last.next_token, None);

        // A page that ends exactly at the last item has no successor.
        assert_eq!(paginate(4, 2, Some("2")).unwrap().next_token, None);
        assert_eq!(paginate(0, 60, None).unwrap().next_token, None);
    }

    #[test]
    fn unusable_next_token_is_rejected() {
        assert!(paginate(5, 2, Some("not-a-token")).is_err());
        assert!(paginate(5, 2, Some("6")).is_err());
    }
}
