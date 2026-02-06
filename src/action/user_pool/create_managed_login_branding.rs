//! CreateManagedLoginBranding API implementation
//!
//! <https://docs.aws.amazon.com/cognito-user-identity-pools/latest/APIReference/API_CreateManagedLoginBranding.html>

use chrono::Utc;
use serde::Deserialize;
use serde_json::{json, Value};
use uuid::Uuid;

use crate::{
    error::{AppError, Result},
    storage::Storage,
    types::{BrandingAssets, BrandingColorSettings, BrandingSettings, ManagedLoginBranding},
};

#[derive(Debug, Deserialize)]
#[serde(rename_all = "PascalCase")]
struct Request {
    user_pool_id: String,
    client_id: Option<String>,
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

    // Validate client if specified
    if let Some(ref client_id) = req.client_id {
        let client = storage.get_user_pool_client(client_id).await;
        match client {
            Some(c) if c.user_pool_id == req.user_pool_id => {}
            _ => return Err(AppError::UserPoolClientNotFound),
        }
    }

    // Check if branding already exists for this user pool
    if storage
        .get_managed_login_branding_by_user_pool(&req.user_pool_id)
        .await
        .is_some()
    {
        return Err(AppError::InvalidParameter(
            "Branding already exists for this user pool".to_string(),
        ));
    }

    let now = Utc::now();
    let branding_id = Uuid::new_v4().to_string();

    let settings = req.settings.map(|s| BrandingSettings {
        colors: s.colors.map(|c| BrandingColorSettings {
            background_color: c.background_color,
            primary_color: c.primary_color,
            secondary_color: c.secondary_color,
            text_color: c.text_color,
            link_color: c.link_color,
            button_color: c.button_color,
            button_text_color: c.button_text_color,
        }),
        page_title: s.page_title,
        sign_in_header: s.sign_in_header,
        sign_in_subheader: s.sign_in_subheader,
    });

    let assets = req.assets.map(|a| BrandingAssets {
        logo_url: a.logo_url,
        favicon_url: a.favicon_url,
        background_image_url: a.background_image_url,
        css_url: a.css_url,
    });

    let branding = ManagedLoginBranding {
        branding_id,
        user_pool_id: req.user_pool_id,
        client_id: req.client_id,
        use_cognito_provided_values: req.use_cognito_provided_values.unwrap_or(true),
        settings,
        assets,
        creation_date: now,
        last_modified_date: now,
    };

    let created = storage.create_managed_login_branding(branding).await;

    Ok(json!({
        "ManagedLoginBranding": build_branding_response(&created)
    }))
}

pub fn build_branding_response(branding: &ManagedLoginBranding) -> Value {
    let mut response = json!({
        "ManagedLoginBrandingId": branding.branding_id,
        "UserPoolId": branding.user_pool_id,
        "UseCognitoProvidedValues": branding.use_cognito_provided_values,
        "CreationDate": branding.creation_date.timestamp(),
        "LastModifiedDate": branding.last_modified_date.timestamp()
    });

    if let Some(ref client_id) = branding.client_id {
        response["ClientId"] = json!(client_id);
    }

    if let Some(ref settings) = branding.settings {
        let mut settings_json = json!({});

        if let Some(ref colors) = settings.colors {
            let mut colors_json = json!({});
            if let Some(ref c) = colors.background_color {
                colors_json["BackgroundColor"] = json!(c);
            }
            if let Some(ref c) = colors.primary_color {
                colors_json["PrimaryColor"] = json!(c);
            }
            if let Some(ref c) = colors.secondary_color {
                colors_json["SecondaryColor"] = json!(c);
            }
            if let Some(ref c) = colors.text_color {
                colors_json["TextColor"] = json!(c);
            }
            if let Some(ref c) = colors.link_color {
                colors_json["LinkColor"] = json!(c);
            }
            if let Some(ref c) = colors.button_color {
                colors_json["ButtonColor"] = json!(c);
            }
            if let Some(ref c) = colors.button_text_color {
                colors_json["ButtonTextColor"] = json!(c);
            }
            settings_json["Colors"] = colors_json;
        }

        if let Some(ref title) = settings.page_title {
            settings_json["PageTitle"] = json!(title);
        }
        if let Some(ref header) = settings.sign_in_header {
            settings_json["SignInHeader"] = json!(header);
        }
        if let Some(ref subheader) = settings.sign_in_subheader {
            settings_json["SignInSubheader"] = json!(subheader);
        }

        response["Settings"] = settings_json;
    }

    if let Some(ref assets) = branding.assets {
        let mut assets_json = json!({});
        if let Some(ref url) = assets.logo_url {
            assets_json["LogoUrl"] = json!(url);
        }
        if let Some(ref url) = assets.favicon_url {
            assets_json["FaviconUrl"] = json!(url);
        }
        if let Some(ref url) = assets.background_image_url {
            assets_json["BackgroundImageUrl"] = json!(url);
        }
        if let Some(ref url) = assets.css_url {
            assets_json["CssUrl"] = json!(url);
        }
        response["Assets"] = assets_json;
    }

    response
}
