//! ListUserImportJobs API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_ListUserImportJobs.html>

use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{UserImportJob, UserPoolId},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: UserPoolId,
    max_results: Option<u32>,
    #[allow(dead_code)]
    pagination_token: Option<String>,
}

fn job_to_json(job: &UserImportJob) -> Value {
    json!({
        "JobId": job.job_id,
        "JobName": job.job_name,
        "UserPoolId": job.user_pool_id,
        "CloudWatchLogsRoleArn": job.cloud_watch_logs_role_arn,
        "JobStatus": job.status,
        "PreSignedUrl": job.pre_signed_url,
        "CreationDate": job.creation_date.timestamp(),
        "StartDate": job.start_date.map(|d| d.timestamp()),
        "CompletionDate": job.completion_date.map(|d| d.timestamp()),
        "CompletionMessage": job.completion_message,
        "ImportedUsers": job.imported_users,
        "SkippedUsers": job.skipped_users,
        "FailedUsers": job.failed_users
    })
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    storage
        .get_user_pool(&req.user_pool_id)
        .await
        .ok_or(AppError::UserPoolNotFound)?;

    let max_results = req.max_results.unwrap_or(60) as usize;
    let jobs = storage
        .list_user_import_jobs(&req.user_pool_id)
        .await
        .into_iter()
        .take(max_results)
        .map(|job| job_to_json(&job))
        .collect::<Vec<_>>();

    Ok(json!({
        "UserImportJobs": jobs,
        "PaginationToken": null
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::{create_user_import_job, create_user_pool};

    #[tokio::test]
    async fn test_list_user_import_jobs_success() {
        let storage = Storage::new();
        let pool = create_user_pool::handler(&storage, json!({"PoolName": "pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        create_user_import_job::handler(
            &storage,
            json!({
                "JobName": "import-job",
                "UserPoolId": pool_id,
                "CloudWatchLogsRoleArn": "arn:aws:iam::123456789012:role/test"
            }),
        )
        .await
        .unwrap();

        let result = handler(&storage, json!({"UserPoolId": pool_id}))
            .await
            .unwrap();

        assert_eq!(result["UserImportJobs"].as_array().unwrap().len(), 1);
    }
}
