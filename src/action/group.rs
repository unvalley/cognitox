pub mod admin_add_user_to_group;
pub mod admin_list_groups_for_user;
pub mod admin_remove_user_from_group;
pub mod create_group;
pub mod delete_group;
pub mod get_group;
pub mod list_groups;
pub mod list_users_in_group;
pub mod update_group;

use serde_json::{Map, Value, json};

use crate::types::Group;

/// `GroupType` as the group operations return it. Like Cognito, a group
/// without a description, role, or precedence simply lacks the member.
pub(crate) fn build_group_response(group: &Group) -> Value {
    let mut response = Map::new();
    response.insert("GroupName".to_string(), json!(group.group_name));
    response.insert("UserPoolId".to_string(), json!(group.user_pool_id));
    if let Some(description) = &group.description {
        response.insert("Description".to_string(), json!(description));
    }
    if let Some(role_arn) = &group.role_arn {
        response.insert("RoleArn".to_string(), json!(role_arn));
    }
    if let Some(precedence) = group.precedence {
        response.insert("Precedence".to_string(), json!(precedence));
    }
    response.insert(
        "LastModifiedDate".to_string(),
        json!(group.last_modified_date.timestamp()),
    );
    response.insert(
        "CreationDate".to_string(),
        json!(group.creation_date.timestamp()),
    );
    Value::Object(response)
}
