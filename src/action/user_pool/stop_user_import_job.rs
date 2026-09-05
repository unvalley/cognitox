//! StopUserImportJob API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_StopUserImportJob.html>

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
    user_pool_id: UserPoolId,
    job_id: String,
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

    let mut job = storage
        .get_user_import_job(&req.job_id)
        .await
        .ok_or(AppError::UserImportJobNotFound)?;

    if job.user_pool_id != req.user_pool_id {
        return Err(AppError::UserImportJobNotFound);
    }

    // Only a running job can be stopped.
    if !matches!(
        job.status,
        UserImportJobStatus::Pending | UserImportJobStatus::InProgress
    ) {
        return Err(AppError::PreconditionNotMet(format!(
            "Job cannot be stopped from status {:?}",
            job.status
        )));
    }

    job.status = UserImportJobStatus::Stopped;
    job.completion_date = Some(Utc::now());
    job.completion_message = Some("Job stopped".to_string());
    storage.update_user_import_job(job.clone()).await;

    Ok(json!({
        "UserImportJob": job_to_json(&job)
    }))
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::action::user_pool::{
        create_user_import_job, create_user_pool, start_user_import_job,
    };

    #[tokio::test]
    async fn test_stop_user_import_job_success() {
        let storage = Storage::new();
        let pool = create_user_pool::handler(&storage, json!({"PoolName": "pool"}))
            .await
            .unwrap();
        let pool_id = pool["UserPool"]["Id"].as_str().unwrap();

        let created = create_user_import_job::handler(
            &storage,
            json!({
                "JobName": "import-job",
                "UserPoolId": pool_id,
                "CloudWatchLogsRoleArn": "arn:aws:iam::123456789012:role/test"
            }),
        )
        .await
        .unwrap();
        let job_id = created["UserImportJob"]["JobId"].as_str().unwrap();

        start_user_import_job::handler(&storage, json!({"UserPoolId": pool_id, "JobId": job_id}))
            .await
            .unwrap();

        let result = handler(&storage, json!({"UserPoolId": pool_id, "JobId": job_id}))
            .await
            .unwrap();

        assert_eq!(result["UserImportJob"]["JobStatus"], "Stopped");
    }
}
