//! Helpers shared by the user operation tests.

use serde_json::json;
use uuid::Uuid;

use crate::storage::Storage;

use super::confirm_sign_up;

/// Confirm a freshly signed-up user the way a client does: by returning the
/// code the emulator "sent". Unlike `Storage::confirm_user`, this also marks
/// the email address or phone number the code went to as verified.
pub(crate) async fn confirm_with_code(storage: &Storage, client_id: &str, user_id: &Uuid) {
    let user = storage.get_user(user_id).await.expect("the user exists");
    let code = storage
        .get_confirmation_code(user_id)
        .await
        .expect("sign-up delivered a confirmation code")
        .code;
    confirm_sign_up::handler(
        storage,
        json!({
            "ClientId": client_id,
            "Username": user.username,
            "ConfirmationCode": code,
        }),
    )
    .await
    .expect("the confirmation code is accepted");
}
