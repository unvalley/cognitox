//! The configuration Cognito fills in for a user pool.
//!
//! A pool created with nothing but a name still has a password policy, an
//! account recovery setting, a schema of standard attributes, and so on, and
//! `DescribeUserPool` returns them. [`apply_user_pool_defaults`] stores those
//! defaults when a pool is created or updated, and the pool view applies them
//! again so that pools from snapshots that predate them read the same way.

use serde_json::json;

use crate::{
    types::{
        AccountRecoverySetting, AdminCreateUserConfig, AttributeDataType, DefaultEmailOption,
        DeletionProtection, EmailConfiguration, EmailSendingAccount, FirstAuthFactor,
        MfaConfiguration, NumberAttributeConstraintsType, PasswordPolicy, RecoveryMechanismName,
        RecoveryOption, SchemaAttributeType, SignInPolicy, StringAttributeConstraintsType,
        UserPool, UserPoolId, UserPoolPolicies, UserPoolTier, UsernameConfiguration,
        VerificationMessageTemplate,
    },
    validation::default_password_policy,
};

/// The AWS account the emulator's resources claim to live in.
pub(crate) const ACCOUNT_ID: &str = "000000000000";

/// `PasswordPolicy.MinimumLength` when a policy leaves it out.
const DEFAULT_MINIMUM_PASSWORD_LENGTH: i32 = 8;

/// Days a temporary password stays valid when the pool does not say.
const DEFAULT_TEMPORARY_PASSWORD_VALIDITY_DAYS: i32 = 7;

/// The region a user pool ID names (`us-east-1_AbCdEfGhI` is in `us-east-1`).
pub(crate) fn user_pool_region(id: &UserPoolId) -> &str {
    id.as_str()
        .split_once('_')
        .map_or(id.as_str(), |(region, _)| region)
}

/// `arn:aws:cognito-idp:<region>:<account>:userpool/<id>`
pub(crate) fn user_pool_arn(id: &UserPoolId) -> String {
    format!(
        "arn:aws:cognito-idp:{}:{ACCOUNT_ID}:userpool/{id}",
        user_pool_region(id)
    )
}

/// Complete a `Policies` value the way Cognito stores it.
///
/// A pool without a password policy gets the default one. In a policy the
/// caller did provide, a requirement that was left out is off: asking for
/// `MinimumLength: 6` does not also ask for symbols.
pub(crate) fn complete_policies(policies: Option<UserPoolPolicies>) -> UserPoolPolicies {
    let (password_policy, sign_in_policy) = match policies {
        Some(policies) => (policies.password_policy, policies.sign_in_policy),
        None => (None, None),
    };

    let password_policy = match password_policy {
        None => default_password_policy(),
        Some(policy) => PasswordPolicy {
            minimum_length: policy
                .minimum_length
                .or(Some(DEFAULT_MINIMUM_PASSWORD_LENGTH)),
            password_history_size: policy.password_history_size,
            require_lowercase: policy.require_lowercase.or(Some(false)),
            require_numbers: policy.require_numbers.or(Some(false)),
            require_symbols: policy.require_symbols.or(Some(false)),
            require_uppercase: policy.require_uppercase.or(Some(false)),
            temporary_password_validity_days: policy
                .temporary_password_validity_days
                .or(Some(DEFAULT_TEMPORARY_PASSWORD_VALIDITY_DAYS)),
        },
    };

    let allowed_first_auth_factors = sign_in_policy
        .and_then(|policy| policy.allowed_first_auth_factors)
        .filter(|factors| !factors.is_empty())
        .unwrap_or_else(|| vec![FirstAuthFactor::Password]);

    UserPoolPolicies {
        password_policy: Some(password_policy),
        sign_in_policy: Some(SignInPolicy {
            allowed_first_auth_factors: Some(allowed_first_auth_factors),
        }),
    }
}

fn default_account_recovery_setting() -> AccountRecoverySetting {
    AccountRecoverySetting {
        recovery_mechanisms: Some(vec![
            RecoveryOption {
                name: RecoveryMechanismName::VerifiedEmail,
                priority: Some(1),
            },
            RecoveryOption {
                name: RecoveryMechanismName::VerifiedPhoneNumber,
                priority: Some(2),
            },
        ]),
    }
}

/// Fill in every setting Cognito defaults, leaving what is set untouched.
pub(crate) fn apply_user_pool_defaults(pool: &mut UserPool) {
    pool.policies = Some(complete_policies(pool.policies.take()));
    pool.mfa_configuration.get_or_insert(MfaConfiguration::Off);
    pool.deletion_protection
        .get_or_insert(DeletionProtection::Inactive);
    pool.lambda_config.get_or_insert_with(|| json!({}));
    pool.user_pool_tier.get_or_insert(UserPoolTier::Essentials);
    // Usernames are case sensitive unless the request says otherwise; the
    // API reference names `true` as the default of `CaseSensitive`.
    pool.username_configuration
        .get_or_insert(UsernameConfiguration {
            case_sensitive: true,
        });
    pool.account_recovery_setting
        .get_or_insert_with(default_account_recovery_setting);

    pool.email_configuration
        .get_or_insert(EmailConfiguration {
            configuration_set: None,
            email_sending_account: None,
            from: None,
            reply_to_email_address: None,
            source_arn: None,
        })
        .email_sending_account
        .get_or_insert(EmailSendingAccount::CognitoDefault);

    // `UnusedAccountValidityDays` is the older name of the password policy's
    // `TemporaryPasswordValidityDays`; Cognito reports the same number in both.
    let temporary_password_validity_days = pool
        .policies
        .as_ref()
        .and_then(|policies| policies.password_policy.as_ref())
        .and_then(|policy| policy.temporary_password_validity_days)
        .unwrap_or(DEFAULT_TEMPORARY_PASSWORD_VALIDITY_DAYS);
    let admin_create_user_config =
        pool.admin_create_user_config
            .get_or_insert(AdminCreateUserConfig {
                allow_admin_create_user_only: None,
                invite_message_template: None,
                unused_account_validity_days: None,
            });
    admin_create_user_config
        .allow_admin_create_user_only
        .get_or_insert(false);
    admin_create_user_config
        .unused_account_validity_days
        .get_or_insert(temporary_password_validity_days);

    pool.verification_message_template
        .get_or_insert(VerificationMessageTemplate {
            default_email_option: None,
            email_message: None,
            email_message_by_link: None,
            email_subject: None,
            email_subject_by_link: None,
            sms_message: None,
        })
        .default_email_option
        .get_or_insert(DefaultEmailOption::ConfirmWithCode);
}

fn standard_attribute(
    name: &str,
    data_type: AttributeDataType,
    string_length: Option<(&str, &str)>,
) -> SchemaAttributeType {
    SchemaAttributeType {
        name: name.to_string(),
        attribute_data_type: Some(data_type),
        developer_only_attribute: Some(false),
        mutable: Some(true),
        number_attribute_constraints: None,
        required: Some(false),
        string_attribute_constraints: string_length.map(|(min_length, max_length)| {
            StringAttributeConstraintsType {
                min_length: Some(min_length.to_string()),
                max_length: Some(max_length.to_string()),
            }
        }),
    }
}

/// The standard (OpenID Connect) attributes every user pool has, in the
/// order and with the constraints Cognito reports.
pub(crate) fn standard_schema_attributes() -> Vec<SchemaAttributeType> {
    use AttributeDataType::{Boolean, Number, String};
    let text = Some(("0", "2048"));

    let mut sub = standard_attribute("sub", String, Some(("1", "2048")));
    sub.mutable = Some(false);
    sub.required = Some(true);

    let mut updated_at = standard_attribute("updated_at", Number, None);
    updated_at.number_attribute_constraints = Some(NumberAttributeConstraintsType {
        min_value: Some("0".to_string()),
        max_value: None,
    });

    let mut identities = standard_attribute("identities", String, None);
    identities.string_attribute_constraints = Some(StringAttributeConstraintsType {
        min_length: None,
        max_length: None,
    });

    vec![
        sub,
        standard_attribute("name", String, text),
        standard_attribute("given_name", String, text),
        standard_attribute("family_name", String, text),
        standard_attribute("middle_name", String, text),
        standard_attribute("nickname", String, text),
        standard_attribute("preferred_username", String, text),
        standard_attribute("profile", String, text),
        standard_attribute("picture", String, text),
        standard_attribute("website", String, text),
        standard_attribute("email", String, text),
        standard_attribute("email_verified", Boolean, None),
        standard_attribute("gender", String, text),
        standard_attribute("birthdate", String, Some(("10", "10"))),
        standard_attribute("zoneinfo", String, text),
        standard_attribute("locale", String, text),
        standard_attribute("phone_number", String, text),
        standard_attribute("phone_number_verified", Boolean, None),
        standard_attribute("address", String, text),
        updated_at,
        identities,
    ]
}

/// `SchemaAttributes` as `DescribeUserPool` returns them: the standard
/// attributes, adjusted by what the pool's schema says about them, followed
/// by the pool's custom attributes under their `custom:` names.
///
/// `stored` is the schema the pool was created with plus the attributes
/// `AddCustomAttributes` added, under the names the caller used.
pub(crate) fn schema_attributes_view(stored: &[SchemaAttributeType]) -> Vec<SchemaAttributeType> {
    let mut schema = standard_schema_attributes();
    let standard_count = schema.len();

    for attribute in stored {
        if let Some(standard) = schema[..standard_count]
            .iter_mut()
            .find(|standard| standard.name == attribute.name)
        {
            if let Some(required) = attribute.required {
                standard.required = Some(required);
            }
            if let Some(mutable) = attribute.mutable {
                standard.mutable = Some(mutable);
            }
            if attribute.string_attribute_constraints.is_some() {
                standard.string_attribute_constraints =
                    attribute.string_attribute_constraints.clone();
            }
            if attribute.number_attribute_constraints.is_some() {
                standard.number_attribute_constraints =
                    attribute.number_attribute_constraints.clone();
            }
            continue;
        }

        let data_type = attribute
            .attribute_data_type
            .unwrap_or(AttributeDataType::String);
        let developer_only = attribute.developer_only_attribute.unwrap_or(false);
        schema.push(SchemaAttributeType {
            name: custom_attribute_name(&attribute.name, developer_only),
            attribute_data_type: Some(data_type),
            developer_only_attribute: Some(developer_only),
            mutable: Some(attribute.mutable.unwrap_or(true)),
            number_attribute_constraints: match data_type {
                AttributeDataType::Number => {
                    Some(attribute.number_attribute_constraints.clone().unwrap_or(
                        NumberAttributeConstraintsType {
                            min_value: None,
                            max_value: None,
                        },
                    ))
                }
                _ => None,
            },
            required: Some(false),
            string_attribute_constraints: match data_type {
                AttributeDataType::String => {
                    Some(attribute.string_attribute_constraints.clone().unwrap_or(
                        StringAttributeConstraintsType {
                            min_length: None,
                            max_length: None,
                        },
                    ))
                }
                _ => None,
            },
        });
    }

    schema
}

/// The name a custom attribute goes by: `custom:<name>`, or
/// `dev:custom:<name>` for a developer-only attribute.
fn custom_attribute_name(name: &str, developer_only: bool) -> String {
    let base = name.strip_prefix("dev:").unwrap_or(name);
    let base = base.strip_prefix("custom:").unwrap_or(base);
    if developer_only {
        format!("dev:custom:{base}")
    } else {
        format!("custom:{base}")
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn pool() -> UserPool {
        UserPool::new_for_test(UserPoolId::new("eu-west-1_Test").unwrap())
    }

    #[test]
    fn arn_names_the_region_of_the_pool_id() {
        let id = UserPoolId::new("eu-west-1_AbCdEfGhI").unwrap();
        assert_eq!(
            user_pool_arn(&id),
            "arn:aws:cognito-idp:eu-west-1:000000000000:userpool/eu-west-1_AbCdEfGhI"
        );
    }

    #[test]
    fn missing_policy_becomes_cognitos_default() {
        let policies = complete_policies(None);
        assert_eq!(policies.password_policy, Some(default_password_policy()));
        assert_eq!(
            policies.sign_in_policy.unwrap().allowed_first_auth_factors,
            Some(vec![FirstAuthFactor::Password])
        );
    }

    #[test]
    fn partial_policy_requires_only_what_was_asked() {
        let policies = complete_policies(Some(UserPoolPolicies {
            password_policy: Some(PasswordPolicy {
                minimum_length: None,
                password_history_size: None,
                require_lowercase: None,
                require_numbers: Some(true),
                require_symbols: None,
                require_uppercase: None,
                temporary_password_validity_days: None,
            }),
            sign_in_policy: None,
        }));
        let policy = policies.password_policy.unwrap();
        assert_eq!(policy.minimum_length, Some(8));
        assert_eq!(policy.require_numbers, Some(true));
        assert_eq!(policy.require_lowercase, Some(false));
        assert_eq!(policy.require_symbols, Some(false));
        assert_eq!(policy.require_uppercase, Some(false));
        assert_eq!(policy.temporary_password_validity_days, Some(7));
    }

    #[test]
    fn defaults_fill_only_what_is_missing() {
        let mut pool = pool();
        pool.mfa_configuration = Some(MfaConfiguration::Optional);
        pool.user_pool_tier = Some(UserPoolTier::Plus);
        pool.admin_create_user_config = Some(AdminCreateUserConfig {
            allow_admin_create_user_only: Some(true),
            invite_message_template: None,
            unused_account_validity_days: None,
        });
        pool.policies = Some(UserPoolPolicies {
            password_policy: Some(PasswordPolicy {
                temporary_password_validity_days: Some(3),
                ..default_password_policy()
            }),
            sign_in_policy: None,
        });

        apply_user_pool_defaults(&mut pool);

        assert_eq!(pool.mfa_configuration, Some(MfaConfiguration::Optional));
        assert_eq!(pool.user_pool_tier, Some(UserPoolTier::Plus));
        assert_eq!(pool.deletion_protection, Some(DeletionProtection::Inactive));
        assert_eq!(pool.lambda_config, Some(json!({})));
        let admin = pool.admin_create_user_config.clone().unwrap();
        assert_eq!(admin.allow_admin_create_user_only, Some(true));
        // Follows the password policy's temporary password validity.
        assert_eq!(admin.unused_account_validity_days, Some(3));
        assert_eq!(
            pool.email_configuration
                .as_ref()
                .unwrap()
                .email_sending_account,
            Some(EmailSendingAccount::CognitoDefault)
        );
        assert_eq!(
            pool.verification_message_template
                .as_ref()
                .unwrap()
                .default_email_option,
            Some(DefaultEmailOption::ConfirmWithCode)
        );

        // Applying the defaults again changes nothing.
        let once = serde_json::to_value(&pool).unwrap();
        apply_user_pool_defaults(&mut pool);
        assert_eq!(serde_json::to_value(&pool).unwrap(), once);
    }

    #[test]
    fn schema_view_lists_standard_then_custom_attributes() {
        let stored = vec![
            SchemaAttributeType {
                name: "email".to_string(),
                attribute_data_type: Some(AttributeDataType::String),
                developer_only_attribute: None,
                mutable: Some(false),
                number_attribute_constraints: None,
                required: Some(true),
                string_attribute_constraints: None,
            },
            SchemaAttributeType {
                name: "tenant".to_string(),
                attribute_data_type: None,
                developer_only_attribute: None,
                mutable: None,
                number_attribute_constraints: None,
                required: None,
                string_attribute_constraints: None,
            },
            SchemaAttributeType {
                name: "custom:seats".to_string(),
                attribute_data_type: Some(AttributeDataType::Number),
                developer_only_attribute: Some(true),
                mutable: Some(false),
                number_attribute_constraints: None,
                required: None,
                string_attribute_constraints: None,
            },
        ];

        let schema = schema_attributes_view(&stored);
        let standard = standard_schema_attributes();
        assert_eq!(schema.len(), standard.len() + 2);
        assert_eq!(schema[0].name, "sub");
        assert_eq!(schema[0].required, Some(true));
        assert_eq!(schema[0].mutable, Some(false));

        let email = schema.iter().find(|a| a.name == "email").unwrap();
        assert_eq!(email.required, Some(true));
        assert_eq!(email.mutable, Some(false));
        assert_eq!(
            email.string_attribute_constraints,
            Some(StringAttributeConstraintsType {
                min_length: Some("0".to_string()),
                max_length: Some("2048".to_string()),
            })
        );

        let tenant = &schema[standard.len()];
        assert_eq!(tenant.name, "custom:tenant");
        assert_eq!(tenant.attribute_data_type, Some(AttributeDataType::String));
        assert_eq!(tenant.mutable, Some(true));
        assert_eq!(tenant.required, Some(false));
        assert!(tenant.string_attribute_constraints.is_some());

        let seats = &schema[standard.len() + 1];
        assert_eq!(seats.name, "dev:custom:seats");
        assert!(seats.number_attribute_constraints.is_some());
        assert!(seats.string_attribute_constraints.is_none());
    }
}
