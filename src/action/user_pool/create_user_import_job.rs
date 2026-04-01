//! CreateUserImportJob API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateUserImportJob.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{UserImportJob, UserImportJobStatus, UserPoolId},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    job_name: String,
    user_pool_id: UserPoolId,
    cloud_watch_logs_role_arn: String,
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

    let now = Utc::now();
    let job = UserImportJob {
        job_id: uuid::Uuid::now_v7().to_string(),
        user_pool_id: req.user_pool_id,
        job_name: req.job_name,
        cloud_watch_logs_role_arn: req.cloud_watch_logs_role_arn,
        status: UserImportJobStatus::Created,
        pre_signed_url: Some("https://example.com/user-import.csv".to_string()),
        creation_date: now,
        start_date: None,
        completion_date: None,
        completion_message: None,
        imported_users: 0,
        skipped_users: 0,
        failed_users: 0,
    };

    let created = storage.create_user_import_job(job).await;

    Ok(json!({"UserImportJob": job_to_json(&created)}))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::create_user_pool;

    #[tokio::test]
    async fn test_create_user_import_job_success() {
        let storage = Storage::new();
        let pool = create_user_pool::handler(&storage, json!({"PoolName": "pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let result = handler(
            &storage,
            json!({
                "JobName": "import-job",
                "UserPoolId": pool_id,
                "CloudWatchLogsRoleArn": "arn:aws:iam::123456789012:role/test"
            }),
        )
        .await
        .unwrap();

        assert_eq!(result["UserImportJob"]["JobName"], "import-job");
    }
}
