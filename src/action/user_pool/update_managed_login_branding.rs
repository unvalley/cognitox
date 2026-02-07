//! UpdateManagedLoginBranding API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_UpdateManagedLoginBranding.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{Value, json};

use super::create_managed_login_branding::build_branding_response;
use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{BrandingAssets, BrandingColorSettings, BrandingSettings, UserPoolId},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    managed_login_branding_id: String,
    user_pool_id: UserPoolId,
    use_cognito_provided_values: Option<bool>,
    settings: Option<SettingsInput>,
    assets: Option<AssetsInput>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct SettingsInput {
    colors: Option<ColorsInput>,
    page_title: Option<String>,
    sign_in_header: Option<String>,
    sign_in_subheader: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct ColorsInput {
    background_color: Option<String>,
    primary_color: Option<String>,
    secondary_color: Option<String>,
    text_color: Option<String>,
    link_color: Option<String>,
    button_color: Option<String>,
    button_text_color: Option<String>,
}

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct AssetsInput {
    logo_url: Option<String>,
    favicon_url: Option<String>,
    background_image_url: Option<String>,
    css_url: Option<String>,
}

pub async fn handler(storage: &Storage, body: Value) -> Result<Value> {
    let req: Request = serde_json::from_value(body)
        .map_err(|e| AppError::InvalidParameter(format!("Invalid request: {}", e)))?;

    // Validate user pool exists
    if storage.get_user_pool(&req.user_pool_id).await.is_none() {
        return Err(AppError::UserPoolNotFound);
    }

    // Get existing branding
    let mut branding = storage
        .get_managed_login_branding(&req.managed_login_branding_id)
        .await
        .ok_or_else(|| {
            AppError::InvalidParameter("Managed login branding not found".to_string())
        })?;

    // Verify it belongs to the specified user pool
    if branding.user_pool_id != req.user_pool_id {
        return Err(AppError::InvalidParameter(
            "Branding does not belong to the specified user pool".to_string(),
        ));
    }

    // Update fields
    if let Some(use_cognito) = req.use_cognito_provided_values {
        branding.use_cognito_provided_values = use_cognito;
    }

    if let Some(settings_input) = req.settings {
        let settings = BrandingSettings {
            colors: settings_input.colors.map(|c| BrandingColorSettings {
                background_color: c.background_color,
                primary_color: c.primary_color,
                secondary_color: c.secondary_color,
                text_color: c.text_color,
                link_color: c.link_color,
                button_color: c.button_color,
                button_text_color: c.button_text_color,
            }),
            page_title: settings_input.page_title,
            sign_in_header: settings_input.sign_in_header,
            sign_in_subheader: settings_input.sign_in_subheader,
        };
        branding.settings = Some(settings);
    }

    if let Some(assets_input) = req.assets {
        let assets = BrandingAssets {
            logo_url: assets_input.logo_url,
            favicon_url: assets_input.favicon_url,
            background_image_url: assets_input.background_image_url,
            css_url: assets_input.css_url,
        };
        branding.assets = Some(assets);
    }

    branding.last_modified_date = Utc::now();

    let updated = storage
        .update_managed_login_branding(branding)
        .await
        .ok_or_else(|| AppError::Internal("Failed to update branding".to_string()))?;

    Ok(json!({
        "ManagedLoginBranding": build_branding_response(&updated)
    }))
}
