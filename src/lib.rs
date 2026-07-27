/*
 * Isabelle project
 *
 * Copyright 2023-2024 Maxim Menshikov
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the “Software”),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included
 * in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED “AS IS”, WITHOUT WARRANTY OF ANY KIND, EXPRESS
 * OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
 * FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
 * DEALINGS IN THE SOFTWARE.
 */
use image::ImageEncoder;
use isabelle_dm::data_model::data_object_action::DataObjectAction;
use isabelle_dm::data_model::item::Item;
use isabelle_dm::data_model::process_result::ProcessResult;
use log::error;
use log::info;
use std::collections::HashMap;
use std::fs;
use std::path::Path;

// Security plugin — actor entry point. Spawned by `register_actor`, the
// task drains `PluginHookMessage`s from its mpsc and dispatches to async
// handlers that talk to core via `CoreHandle`. All non-trivial trait-mode
// hooks (password challenge, unique-login/email check, avatar get/upload,
// item-list filter, collection-read, OTP send) are ported to native
// async; unsupported routes return `WebResponse::NotImplemented`.

use isabelle_plugin_api::actor::{
    CollectionReadReply, CoreHandle, ListFilterReply, PluginHookMessage, PluginRegistry,
    PreEditReply,
};
use isabelle_plugin_api::api::WebResponse;
use tokio::sync::mpsc;

/// Uploaded avatar source files larger than this are rejected before decode.
const MAX_AVATAR_FILE_BYTES: u64 = 10 * 1024 * 1024;
/// Uploaded avatar images wider/taller than this are rejected by the decoder.
const MAX_AVATAR_DIMENSION: u32 = 8192;

/// Compare two secrets without early exit so the comparison time doesn't
/// reveal how many leading characters matched. Length is still observable,
/// which is fine for fixed-format OTP codes.
fn constant_time_eq(a: &str, b: &str) -> bool {
    let a = a.as_bytes();
    let b = b.as_bytes();
    if a.len() != b.len() {
        return false;
    }
    let mut diff = 0u8;
    for (x, y) in a.iter().zip(b.iter()) {
        diff |= x ^ y;
    }
    diff == 0
}

pub fn register_actor(reg: &mut PluginRegistry, core: CoreHandle) {
    let (tx, rx) = mpsc::channel(64);
    actix_rt::spawn(run_actor(rx, core));
    reg.add("security", tx);
}

async fn run_actor(mut rx: mpsc::Receiver<PluginHookMessage>, core: CoreHandle) {
    while let Some(msg) = rx.recv().await {
        match msg {
            PluginHookMessage::Ping { reply } => {
                let _ = reply.send(());
            }

            PluginHookMessage::ItemPreEdit {
                hndl,
                user,
                collection,
                old_item,
                item,
                action,
                merge,
                reply,
            } => {
                let r = match hndl.as_str() {
                    "security_password_challenge_pre_edit_hook" => {
                        challenge_pre_edit_hook_async(
                            &core,
                            &user,
                            &collection,
                            old_item,
                            item,
                            action,
                            merge,
                        )
                        .await
                    }
                    "security_check_unique_login_email" => {
                        check_unique_login_email_async(&core, old_item, item, action, merge).await
                    }
                    _ => PreEditReply::ok_unchanged(),
                };
                let _ = reply.send(r);
            }

            PluginHookMessage::ItemPostEdit { .. } => {
                // Trait impl was a no-op.
            }

            PluginHookMessage::ItemAuth { reply, .. } => {
                // Trait impl always returned `true`.
                let _ = reply.send(true);
            }

            PluginHookMessage::ItemListFilter {
                hndl,
                user,
                collection,
                context,
                items,
                reply,
            } => {
                let out = if hndl == "security_itm_filter_hook" {
                    item_list_filter_async(&core, &user, &collection, &context, items).await
                } else {
                    ListFilterReply { items }
                };
                let _ = reply.send(out);
            }

            PluginHookMessage::ItemListDbFilter { reply, .. } => {
                let _ = reply.send(String::new());
            }

            PluginHookMessage::CollectionRead {
                hndl,
                collection,
                item,
                reply,
            } => {
                let r = if hndl == "security_collection_read_hook" {
                    collection_read_async(&core, &collection, item).await
                } else {
                    CollectionReadReply::default()
                };
                let _ = reply.send(r);
            }

            PluginHookMessage::Otp { hndl, item } => {
                if hndl == "security_otp_send_email" {
                    otp_send_email_async(&core, &item).await;
                }
            }

            PluginHookMessage::PeriodicJob { .. } => {
                // Trait impl had no periodic hook.
            }

            PluginHookMessage::RouteUrl {
                hndl,
                user,
                query,
                reply,
            } => {
                let r = match hndl.as_str() {
                    "security_get_avatar" => get_avatar_async(&core, &user, &query).await,
                    _ => WebResponse::NotImplemented,
                };
                let _ = reply.send(r);
            }

            PluginHookMessage::RouteUrlPost {
                hndl,
                user,
                query,
                item,
                reply,
            } => {
                let r = match hndl.as_str() {
                    "security_upload_avatar" => {
                        upload_avatar_async(&core, &user, &query, &item).await
                    }
                    _ => WebResponse::NotImplemented,
                };
                let _ = reply.send(r);
            }

            PluginHookMessage::RouteUnprotectedUrl { reply, .. } => {
                let _ = reply.send(WebResponse::NotImplemented);
            }
            PluginHookMessage::RouteUnprotectedUrlPost { reply, .. } => {
                let _ = reply.send(WebResponse::NotImplemented);
            }
            PluginHookMessage::RouteRest { reply, .. } => {
                let _ = reply.send(WebResponse::NotImplemented);
            }

            PluginHookMessage::Shutdown => break,

            _ => {
                // PluginHookMessage is #[non_exhaustive]; ignore future variants.
            }
        }
    }
}

// ---------------------------------------------------------------------------
// async helpers (one per ported hook). They take &CoreHandle for callbacks,
// take Items by value, and return reply structs. Logic mirrors the
// corresponding sync trait method one-to-one.
// ---------------------------------------------------------------------------

async fn check_unique_login_email_async(
    core: &CoreHandle,
    old_itm: Option<Item>,
    itm: Item,
    action: DataObjectAction,
    merge: bool,
) -> PreEditReply {
    let mut itm_upd = old_itm.unwrap_or_else(Item::new);
    if merge {
        itm_upd.merge(&itm);
    } else {
        itm_upd = itm.clone();
    }
    if action == DataObjectAction::Delete {
        return PreEditReply::ok_unchanged();
    }
    let email = itm_upd.safe_str("email", "").to_lowercase();
    let login = itm_upd.safe_str("login", "").to_lowercase();

    if email.is_empty() {
        return PreEditReply::rejected("E-Mail must not be empty");
    }

    let users = core.db_get_all_items("user", "id", "").await;
    for usr in &users.map {
        if *usr.0 != itm.id {
            if !login.is_empty() && login == usr.1.safe_str("login", "").to_lowercase() {
                return PreEditReply::rejected("Login mustn't match already existing one");
            }
            if email == usr.1.safe_str("email", "").to_lowercase() {
                return PreEditReply::rejected("E-Mail mustn't match already existing one");
            }
        }
    }
    PreEditReply::ok_unchanged()
}

async fn challenge_pre_edit_hook_async(
    core: &CoreHandle,
    user: &Option<Item>,
    collection: &str,
    old_itm: Option<Item>,
    mut itm: Item,
    action: DataObjectAction,
    _merge: bool,
) -> PreEditReply {
    let mut salt: String = "<empty salt>".to_string();
    let is_admin = core.auth_check_role(user, "admin").await;

    if action == DataObjectAction::Delete {
        return PreEditReply::ok_unchanged();
    }

    if collection == "user"
        && old_itm.is_some()
        && (itm.strs.contains_key("password") || itm.strs.contains_key("salt"))
    {
        error!("Can't edit password directly");
        return PreEditReply::rejected("Can't edit password directly");
    }

    if collection == "user" {
        match old_itm.as_ref() {
            None => {
                salt = core.auth_get_new_salt().await;
                itm.set_str("salt", &salt);
                // An initial password on creation arrives in plaintext; hash
                // it right away so it is never persisted raw. (The
                // collection-read rehash never fires for this item because
                // the salt is already set above.)
                if itm.strs.contains_key("password") {
                    let pw = itm.safe_str("password", "");
                    let hash = core.auth_get_password_hash(&pw, &salt).await;
                    itm.set_str("password", &hash);
                }
            }
            Some(old) => {
                salt = old.safe_str("salt", "<empty salt>");
            }
        }
    }

    if let Some(old) = old_itm.as_ref().filter(|_| {
        collection == "user"
            && itm.strs.contains_key("__password")
            && itm.strs.contains_key("__new_password1")
            && itm.strs.contains_key("__new_password2")
    }) {
        let old_pw_hash = old.safe_str("password", "");
        let old_otp = old.safe_str("otp", "");
        let old_checked_pw = itm.safe_str("__password", "");
        if !is_admin && old_checked_pw.is_empty() {
            error!("Old password is empty");
            return PreEditReply::rejected("Old password is empty");
        }
        let res = is_admin
            || (!old_pw_hash.is_empty()
                && core
                    .auth_verify_password(&old_checked_pw, &old_pw_hash)
                    .await)
            || (!old_otp.is_empty() && constant_time_eq(&old_otp, &old_checked_pw));
        if !res
            || itm.safe_str("__new_password1", "<bad1>")
                != itm.safe_str("__new_password2", "<bad2>")
        {
            error!("Password change challenge failed");
            return PreEditReply::rejected("Password change challenge failed");
        }
        let new_pw = itm.safe_str("__new_password1", "");
        itm.strs.remove("__password");
        itm.strs.remove("__new_password1");
        itm.strs.remove("__new_password2");
        // Invalidate the OTP: an explicit empty value survives the
        // dispatcher's merge into the stored item, unlike a removed key.
        itm.set_str("otp", "");

        let pw_hash = core.auth_get_password_hash(&new_pw, &salt).await;
        itm.set_str("password", &pw_hash);
    }

    PreEditReply {
        result: ProcessResult {
            succeeded: true,
            error: String::new(),
            data: HashMap::new(),
        },
        modified_item: Some(itm),
    }
}

async fn item_list_filter_async(
    core: &CoreHandle,
    user: &Option<Item>,
    collection: &str,
    context: &str,
    map: HashMap<u64, Item>,
) -> ListFilterReply {
    if collection != "user" {
        return ListFilterReply { items: map };
    }

    let list = context != "full";
    let mut short_map: HashMap<u64, Item> = HashMap::new();
    let user_id = match user.as_ref() {
        Some(u) => u.id,
        None => {
            // No user → empty result.
            return ListFilterReply { items: short_map };
        }
    };

    let is_admin = core.auth_check_role(user, "admin").await;
    info!("Checking collection {} user id {}", collection, user_id);

    if list {
        for el in &map {
            if *el.0 == user_id || is_admin || el.1.safe_bool("__security_preserve", false) {
                let mut itm = Item::new();
                itm.id = *el.0;
                itm.strs
                    .insert("name".to_string(), el.1.safe_str("name", ""));
                itm.bools.insert(
                    "role_is_active".to_string(),
                    el.1.safe_bool("role_is_active", false),
                );
                itm.bools.insert(
                    "role_is_admin".to_string(),
                    el.1.safe_bool("role_is_admin", false),
                );
                short_map.insert(*el.0, itm);
            } else {
                let mut itm = Item::new();
                itm.id = *el.0;
                itm.strs
                    .insert("name".to_string(), el.1.safe_str("name", ""));
                short_map.insert(*el.0, itm);
            }
        }
    } else {
        for el in &map {
            if *el.0 != user_id && !is_admin && !el.1.safe_bool("__security_preserve", false) {
                /* skip */
            } else {
                let mut itm = el.1.clone();
                itm.strs.remove("salt");
                itm.strs.remove("password");
                itm.strs.remove("otp");
                short_map.insert(*el.0, itm);
            }
        }
    }
    ListFilterReply { items: short_map }
}

async fn collection_read_async(
    core: &CoreHandle,
    collection: &str,
    mut itm: Item,
) -> CollectionReadReply {
    if collection != "user" {
        return CollectionReadReply::default();
    }
    if !itm.strs.contains_key("salt") {
        let salt = core.auth_get_new_salt().await;
        itm.set_str("salt", &salt);
        info!("There is no salt for user {}, created new", itm.id);
        if itm.strs.contains_key("password") {
            let pw_old = itm.safe_str("password", "");
            let hash = core.auth_get_password_hash(&pw_old, &salt).await;
            itm.set_str("password", &hash);
            info!("Rehashed password for user {}", itm.id);
        }
        return CollectionReadReply {
            should_save: true,
            item: Some(itm),
        };
    }
    CollectionReadReply::default()
}

async fn get_avatar_async(core: &CoreHandle, user: &Option<Item>, query: &str) -> WebResponse {
    if user.is_none() {
        return WebResponse::Forbidden;
    }
    let data_path = core.globals_get_data_path().await;
    let q: HashMap<String, String> = serde_urlencoded::from_str(query).unwrap_or_default();
    let mut target_id: Option<u64> = None;
    if let Some(id_str) = q.get("id") {
        if id_str == "me" {
            target_id = Some(user.as_ref().unwrap().id);
        } else if let Ok(id) = id_str.parse::<u64>() {
            target_id = Some(id);
        }
    }
    let uid = match target_id {
        Some(v) => v,
        None => return WebResponse::BadRequest,
    };
    let path = format!("{}/user-avatars/{}.bin", data_path, uid);
    WebResponse::OkFilePath("avatar".to_string(), path)
}

async fn upload_avatar_async(
    core: &CoreHandle,
    user: &Option<Item>,
    query: &str,
    post_itm: &Item,
) -> WebResponse {
    // Authentication and target resolution come first: every code path
    // below writes to disk, so nothing may run before authorization.
    let user_itm = match user.as_ref() {
        Some(u) => u,
        None => return WebResponse::Unauthorized,
    };
    let q: HashMap<String, String> = serde_urlencoded::from_str(query).unwrap_or_default();
    let target_id = match q.get("id").map(|s| s.as_str()) {
        None | Some("me") => user_itm.id,
        Some(id_str) => match id_str.parse::<u64>() {
            Ok(id) => id,
            Err(_) => return WebResponse::BadRequest,
        },
    };
    if target_id != user_itm.id && !core.auth_check_role(user, "admin").await {
        return WebResponse::Unauthorized;
    }

    let data_path = core.globals_get_data_path().await;
    let files = post_itm.safe_strstr("multipart-files", &HashMap::new());

    let dir_path = format!("{}/user-avatars", data_path);
    let dir = Path::new(&dir_path);
    if !dir.exists() {
        let _ = fs::create_dir_all(dir);
    }

    let dst = format!("{}/user-avatars/{}.bin", data_path, target_id);

    if let Some(file) = files.into_iter().next() {
        // Fixed staging name: the client-supplied file name must never
        // influence a path on disk (its "extension" may contain path
        // separators). The image format is detected from content below.
        let new_path = format!("{}/user-avatars/{}.stage", data_path, target_id);
        if fs::rename(file.1.clone(), new_path.clone()).is_err() {
            return WebResponse::BadRequest;
        }

        match fs::metadata(&new_path) {
            Ok(md) if md.len() <= MAX_AVATAR_FILE_BYTES => {}
            _ => {
                error!("Avatar upload for user {} exceeds size limit", target_id);
                let _ = fs::remove_file(new_path.clone());
                return WebResponse::BadRequest;
            }
        }

        let decoded = image::ImageReader::open(&new_path)
            .and_then(|r| r.with_guessed_format())
            .map_err(image::ImageError::IoError)
            .and_then(|mut r| {
                let mut limits = image::Limits::default();
                limits.max_image_width = Some(MAX_AVATAR_DIMENSION);
                limits.max_image_height = Some(MAX_AVATAR_DIMENSION);
                r.limits(limits);
                r.decode()
            });
        match decoded {
            Ok(img) => {
                let img = img.resize(256, 256, image::imageops::FilterType::Lanczos3);
                let img = img.to_rgba8();
                let mut out: Vec<u8> = Vec::new();
                let encoder = image::codecs::png::PngEncoder::new(&mut out);
                if let Err(e) = encoder.write_image(
                    &img,
                    img.width(),
                    img.height(),
                    image::ColorType::Rgba8.into(),
                ) {
                    error!("Failed to encode avatar PNG for {}: {}", file.1, e);
                    let _ = fs::remove_file(new_path.clone());
                    return WebResponse::BadRequest;
                }
                if let Err(e) = fs::write(dst.clone(), out) {
                    error!("Failed to write avatar file {}: {}", dst, e);
                    let _ = fs::remove_file(new_path.clone());
                    return WebResponse::BadRequest;
                }
                let _ = fs::remove_file(new_path.clone());
                return WebResponse::Ok;
            }
            Err(e) => {
                error!("Failed to open uploaded image {}: {}", file.1, e);
                let _ = fs::remove_file(new_path.clone());
                return WebResponse::BadRequest;
            }
        }
    }
    WebResponse::BadRequest
}

async fn otp_send_email_async(core: &CoreHandle, itm: &Item) {
    let email = itm.safe_str("email", "");
    let otp = itm.safe_str("otp", "");
    if email.is_empty() || otp.is_empty() {
        return;
    }
    core.send_email(
        &email,
        "Your login code",
        &format!("Enter this as password: {}", otp),
    )
    .await;
}

#[cfg(test)]
mod tests {
    use super::*;
    use isabelle_dm::data_model::list_result::ListResult;
    use isabelle_plugin_api::actor::CoreMessage;
    use std::sync::{Arc, Mutex};

    // -----------------------------------------------------------------------
    // Mock core: answers CoreMessage requests against an in-memory user map.
    // Password hash format: "H(<password>|<salt>)"; verification checks the
    // prefix, salts are always "NEWSALT".
    // -----------------------------------------------------------------------

    type SentEmails = Arc<Mutex<Vec<(String, String, String)>>>;

    fn mock_core(users: HashMap<u64, Item>, data_path: &str) -> (CoreHandle, SentEmails) {
        let (tx, mut rx) = mpsc::channel::<CoreMessage>(64);
        let emails: SentEmails = Arc::new(Mutex::new(Vec::new()));
        let emails_writer = emails.clone();
        let data_path = data_path.to_string();
        tokio::spawn(async move {
            while let Some(msg) = rx.recv().await {
                match msg {
                    CoreMessage::DbGetAllItems {
                        collection, reply, ..
                    } => {
                        let map = if collection == "user" {
                            users.clone()
                        } else {
                            HashMap::new()
                        };
                        let total_count = map.len() as u64;
                        let _ = reply.send(ListResult { map, total_count });
                    }
                    CoreMessage::AuthCheckRole { item, role, reply } => {
                        let allowed = item
                            .map(|i| i.safe_bool(&format!("role_is_{}", role), false))
                            .unwrap_or(false);
                        let _ = reply.send(allowed);
                    }
                    CoreMessage::AuthGetNewSalt { reply } => {
                        let _ = reply.send("NEWSALT".to_string());
                    }
                    CoreMessage::AuthGetPasswordHash {
                        password,
                        salt,
                        reply,
                    } => {
                        let _ = reply.send(format!("H({}|{})", password, salt));
                    }
                    CoreMessage::AuthVerifyPassword {
                        password,
                        hash,
                        reply,
                    } => {
                        let _ = reply.send(hash.starts_with(&format!("H({}|", password)));
                    }
                    CoreMessage::GlobalsGetDataPath { reply } => {
                        let _ = reply.send(data_path.clone());
                    }
                    CoreMessage::SendEmail { to, subject, body } => {
                        emails_writer.lock().unwrap().push((to, subject, body));
                    }
                    // Unhandled variants: drop the message; CoreHandle then
                    // resolves to its documented default value.
                    _ => {}
                }
            }
        });
        (CoreHandle::new(tx), emails)
    }

    fn user(id: u64, login: &str, email: &str) -> Item {
        let mut itm = Item::new();
        itm.id = id;
        itm.set_str("login", login);
        itm.set_str("email", email);
        itm.set_str("name", &format!("User {}", id));
        itm
    }

    fn admin(id: u64, login: &str, email: &str) -> Item {
        let mut itm = user(id, login, email);
        itm.set_bool("role_is_admin", true);
        itm
    }

    fn existing_users() -> HashMap<u64, Item> {
        let mut m = HashMap::new();
        m.insert(1, user(1, "alice", "alice@example.com"));
        m.insert(2, user(2, "bob", "bob@example.com"));
        m
    }

    // -----------------------------------------------------------------------
    // constant_time_eq
    // -----------------------------------------------------------------------

    #[test]
    fn constant_time_eq_basic() {
        assert!(constant_time_eq("123456", "123456"));
        assert!(!constant_time_eq("123456", "123457"));
        assert!(!constant_time_eq("123456", "12345"));
        assert!(constant_time_eq("", ""));
    }

    // -----------------------------------------------------------------------
    // check_unique_login_email
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn unique_check_rejects_empty_email() {
        let (core, _) = mock_core(existing_users(), "");
        let mut itm = Item::new();
        itm.id = 3;
        itm.set_str("login", "carol");
        let r =
            check_unique_login_email_async(&core, None, itm, DataObjectAction::Modify, false).await;
        assert!(!r.result.succeeded);
    }

    #[tokio::test]
    async fn unique_check_rejects_duplicate_email_case_insensitive() {
        let (core, _) = mock_core(existing_users(), "");
        let mut itm = Item::new();
        itm.id = 3;
        itm.set_str("login", "carol");
        itm.set_str("email", "ALICE@example.com");
        let r =
            check_unique_login_email_async(&core, None, itm, DataObjectAction::Modify, false).await;
        assert!(!r.result.succeeded);
    }

    #[tokio::test]
    async fn unique_check_rejects_duplicate_login() {
        let (core, _) = mock_core(existing_users(), "");
        let mut itm = Item::new();
        itm.id = 3;
        itm.set_str("login", "Bob");
        itm.set_str("email", "new@example.com");
        let r =
            check_unique_login_email_async(&core, None, itm, DataObjectAction::Modify, false).await;
        assert!(!r.result.succeeded);
    }

    #[tokio::test]
    async fn unique_check_allows_own_item_and_new_values() {
        let (core, _) = mock_core(existing_users(), "");
        // Alice edits herself, keeping her own login/email — allowed.
        let r = check_unique_login_email_async(
            &core,
            Some(user(1, "alice", "alice@example.com")),
            user(1, "alice", "alice@example.com"),
            DataObjectAction::Modify,
            false,
        )
        .await;
        assert!(r.result.succeeded);

        // Fresh unique user — allowed.
        let r = check_unique_login_email_async(
            &core,
            None,
            user(3, "carol", "carol@example.com"),
            DataObjectAction::Modify,
            false,
        )
        .await;
        assert!(r.result.succeeded);
    }

    #[tokio::test]
    async fn unique_check_skips_delete() {
        let (core, _) = mock_core(existing_users(), "");
        let r = check_unique_login_email_async(
            &core,
            Some(user(1, "alice", "alice@example.com")),
            Item::new(),
            DataObjectAction::Delete,
            true,
        )
        .await;
        assert!(r.result.succeeded);
    }

    #[tokio::test]
    async fn unique_check_uses_merged_login_from_old_item() {
        // Merge update that doesn't touch login/email keeps the old ones and
        // must not clash with *other* users only.
        let (core, _) = mock_core(existing_users(), "");
        let mut delta = Item::new();
        delta.id = 1;
        delta.set_str("name", "Alice Renamed");
        let r = check_unique_login_email_async(
            &core,
            Some(user(1, "alice", "alice@example.com")),
            delta,
            DataObjectAction::Modify,
            true,
        )
        .await;
        assert!(r.result.succeeded);
    }

    // -----------------------------------------------------------------------
    // challenge_pre_edit_hook
    // -----------------------------------------------------------------------

    fn stored_user_with_password(id: u64) -> Item {
        let mut itm = user(id, "alice", "alice@example.com");
        itm.set_str("salt", "OLDSALT");
        itm.set_str("password", "H(oldpw|OLDSALT)");
        itm
    }

    fn pw_change_delta(old_pw: &str, new1: &str, new2: &str) -> Item {
        let mut itm = Item::new();
        itm.id = 1;
        itm.set_str("__password", old_pw);
        itm.set_str("__new_password1", new1);
        itm.set_str("__new_password2", new2);
        itm
    }

    #[tokio::test]
    async fn challenge_rejects_direct_password_edit() {
        let (core, _) = mock_core(HashMap::new(), "");
        let mut itm = Item::new();
        itm.id = 1;
        itm.set_str("password", "H(evil|X)");
        let r = challenge_pre_edit_hook_async(
            &core,
            &Some(user(1, "alice", "a@e.com")),
            "user",
            Some(stored_user_with_password(1)),
            itm,
            DataObjectAction::Modify,
            true,
        )
        .await;
        assert!(!r.result.succeeded);

        let mut itm = Item::new();
        itm.id = 1;
        itm.set_str("salt", "attacker-salt");
        let r = challenge_pre_edit_hook_async(
            &core,
            &Some(user(1, "alice", "a@e.com")),
            "user",
            Some(stored_user_with_password(1)),
            itm,
            DataObjectAction::Modify,
            true,
        )
        .await;
        assert!(!r.result.succeeded);
    }

    #[tokio::test]
    async fn challenge_accepts_correct_old_password() {
        let (core, _) = mock_core(HashMap::new(), "");
        let r = challenge_pre_edit_hook_async(
            &core,
            &Some(user(1, "alice", "a@e.com")),
            "user",
            Some(stored_user_with_password(1)),
            pw_change_delta("oldpw", "newpw", "newpw"),
            DataObjectAction::Modify,
            true,
        )
        .await;
        assert!(r.result.succeeded);
        let out = r.modified_item.expect("modified item");
        assert_eq!(out.safe_str("password", ""), "H(newpw|OLDSALT)");
        assert!(!out.strs.contains_key("__password"));
        assert!(!out.strs.contains_key("__new_password1"));
        assert!(!out.strs.contains_key("__new_password2"));
    }

    #[tokio::test]
    async fn challenge_rejects_wrong_old_password() {
        let (core, _) = mock_core(HashMap::new(), "");
        let r = challenge_pre_edit_hook_async(
            &core,
            &Some(user(1, "alice", "a@e.com")),
            "user",
            Some(stored_user_with_password(1)),
            pw_change_delta("WRONG", "newpw", "newpw"),
            DataObjectAction::Modify,
            true,
        )
        .await;
        assert!(!r.result.succeeded);
    }

    #[tokio::test]
    async fn challenge_rejects_empty_old_password_for_non_admin() {
        let (core, _) = mock_core(HashMap::new(), "");
        let r = challenge_pre_edit_hook_async(
            &core,
            &Some(user(1, "alice", "a@e.com")),
            "user",
            Some(stored_user_with_password(1)),
            pw_change_delta("", "newpw", "newpw"),
            DataObjectAction::Modify,
            true,
        )
        .await;
        assert!(!r.result.succeeded);
    }

    #[tokio::test]
    async fn challenge_rejects_mismatched_new_passwords() {
        let (core, _) = mock_core(HashMap::new(), "");
        let r = challenge_pre_edit_hook_async(
            &core,
            &Some(user(1, "alice", "a@e.com")),
            "user",
            Some(stored_user_with_password(1)),
            pw_change_delta("oldpw", "newpw1", "newpw2"),
            DataObjectAction::Modify,
            true,
        )
        .await;
        assert!(!r.result.succeeded);
    }

    #[tokio::test]
    async fn challenge_accepts_otp_and_invalidates_it() {
        let (core, _) = mock_core(HashMap::new(), "");
        let mut stored = stored_user_with_password(1);
        stored.set_str("otp", "123456");
        let r = challenge_pre_edit_hook_async(
            &core,
            &Some(user(1, "alice", "a@e.com")),
            "user",
            Some(stored),
            pw_change_delta("123456", "newpw", "newpw"),
            DataObjectAction::Modify,
            true,
        )
        .await;
        assert!(r.result.succeeded);
        let out = r.modified_item.expect("modified item");
        // OTP must be overwritten with an empty value (merge semantics:
        // a removed key would leave the stored OTP alive and reusable).
        assert_eq!(out.strs.get("otp").map(String::as_str), Some(""));
        assert_eq!(out.safe_str("password", ""), "H(newpw|OLDSALT)");
    }

    #[tokio::test]
    async fn challenge_admin_changes_password_without_old_one() {
        let (core, _) = mock_core(HashMap::new(), "");
        let r = challenge_pre_edit_hook_async(
            &core,
            &Some(admin(9, "root", "root@e.com")),
            "user",
            Some(stored_user_with_password(1)),
            pw_change_delta("", "newpw", "newpw"),
            DataObjectAction::Modify,
            true,
        )
        .await;
        assert!(r.result.succeeded);
        assert_eq!(
            r.modified_item.unwrap().safe_str("password", ""),
            "H(newpw|OLDSALT)"
        );
    }

    #[tokio::test]
    async fn challenge_hashes_initial_password_on_create() {
        let (core, _) = mock_core(HashMap::new(), "");
        let mut itm = user(5, "carol", "carol@e.com");
        itm.set_str("password", "initialpw");
        let r = challenge_pre_edit_hook_async(
            &core,
            &Some(admin(9, "root", "root@e.com")),
            "user",
            None,
            itm,
            DataObjectAction::Modify,
            false,
        )
        .await;
        assert!(r.result.succeeded);
        let out = r.modified_item.expect("modified item");
        assert_eq!(out.safe_str("salt", ""), "NEWSALT");
        // The plaintext initial password must never be persisted raw.
        assert_eq!(out.safe_str("password", ""), "H(initialpw|NEWSALT)");
    }

    #[tokio::test]
    async fn challenge_skips_delete() {
        let (core, _) = mock_core(HashMap::new(), "");
        let mut itm = Item::new();
        itm.set_str("password", "whatever");
        let r = challenge_pre_edit_hook_async(
            &core,
            &Some(admin(9, "root", "root@e.com")),
            "user",
            Some(stored_user_with_password(1)),
            itm,
            DataObjectAction::Delete,
            true,
        )
        .await;
        assert!(r.result.succeeded);
        assert!(r.modified_item.is_none());
    }

    // -----------------------------------------------------------------------
    // item_list_filter
    // -----------------------------------------------------------------------

    fn stored_user_with_secrets(id: u64) -> Item {
        let mut itm = user(id, &format!("login{}", id), &format!("u{}@e.com", id));
        itm.set_str("salt", "SALT");
        itm.set_str("password", "H(pw|SALT)");
        itm.set_str("otp", "123456");
        itm.set_bool("role_is_active", true);
        itm
    }

    #[tokio::test]
    async fn filter_passes_through_non_user_collections() {
        let (core, _) = mock_core(HashMap::new(), "");
        let mut map = HashMap::new();
        map.insert(1, stored_user_with_secrets(1));
        let r = item_list_filter_async(
            &core,
            &Some(user(1, "alice", "a@e.com")),
            "job",
            "full",
            map.clone(),
        )
        .await;
        assert_eq!(r.items.len(), 1);
        assert!(r.items[&1].strs.contains_key("password"));
    }

    #[tokio::test]
    async fn filter_returns_empty_without_user() {
        let (core, _) = mock_core(HashMap::new(), "");
        let mut map = HashMap::new();
        map.insert(1, stored_user_with_secrets(1));
        let r = item_list_filter_async(&core, &None, "user", "full", map).await;
        assert!(r.items.is_empty());
    }

    #[tokio::test]
    async fn filter_full_strips_all_secrets() {
        let (core, _) = mock_core(HashMap::new(), "");
        let mut map = HashMap::new();
        map.insert(1, stored_user_with_secrets(1));
        let r = item_list_filter_async(
            &core,
            &Some(user(1, "alice", "a@e.com")),
            "user",
            "full",
            map,
        )
        .await;
        let itm = &r.items[&1];
        assert!(!itm.strs.contains_key("password"));
        assert!(!itm.strs.contains_key("salt"));
        assert!(!itm.strs.contains_key("otp"));
        assert!(itm.strs.contains_key("email"));
    }

    #[tokio::test]
    async fn filter_full_hides_other_users_from_non_admin() {
        let (core, _) = mock_core(HashMap::new(), "");
        let mut map = HashMap::new();
        map.insert(1, stored_user_with_secrets(1));
        map.insert(2, stored_user_with_secrets(2));
        let r = item_list_filter_async(
            &core,
            &Some(user(1, "alice", "a@e.com")),
            "user",
            "full",
            map,
        )
        .await;
        assert!(r.items.contains_key(&1));
        assert!(!r.items.contains_key(&2));
    }

    #[tokio::test]
    async fn filter_full_shows_all_users_to_admin_without_secrets() {
        let (core, _) = mock_core(HashMap::new(), "");
        let mut map = HashMap::new();
        map.insert(1, stored_user_with_secrets(1));
        map.insert(2, stored_user_with_secrets(2));
        let r = item_list_filter_async(
            &core,
            &Some(admin(9, "root", "root@e.com")),
            "user",
            "full",
            map,
        )
        .await;
        assert_eq!(r.items.len(), 2);
        for itm in r.items.values() {
            assert!(!itm.strs.contains_key("password"));
            assert!(!itm.strs.contains_key("salt"));
            assert!(!itm.strs.contains_key("otp"));
        }
    }

    #[tokio::test]
    async fn filter_list_context_exposes_only_name_and_roles() {
        let (core, _) = mock_core(HashMap::new(), "");
        let mut map = HashMap::new();
        map.insert(1, stored_user_with_secrets(1));
        map.insert(2, stored_user_with_secrets(2));
        let r = item_list_filter_async(
            &core,
            &Some(user(1, "alice", "a@e.com")),
            "user",
            "list",
            map,
        )
        .await;
        assert_eq!(r.items.len(), 2);
        for itm in r.items.values() {
            assert!(!itm.strs.contains_key("password"));
            assert!(!itm.strs.contains_key("salt"));
            assert!(!itm.strs.contains_key("otp"));
            assert!(!itm.strs.contains_key("email"));
            assert!(itm.strs.contains_key("name"));
        }
        // Foreign user: name only, no role flags.
        assert!(!r.items[&2].bools.contains_key("role_is_admin"));
        // Own row keeps role flags.
        assert!(r.items[&1].bools.contains_key("role_is_admin"));
    }

    // -----------------------------------------------------------------------
    // collection_read
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn collection_read_creates_salt_and_rehashes_plaintext() {
        let (core, _) = mock_core(HashMap::new(), "");
        let mut itm = user(1, "alice", "a@e.com");
        itm.set_str("password", "plaintext");
        let r = collection_read_async(&core, "user", itm).await;
        assert!(r.should_save);
        let out = r.item.expect("item");
        assert_eq!(out.safe_str("salt", ""), "NEWSALT");
        assert_eq!(out.safe_str("password", ""), "H(plaintext|NEWSALT)");
    }

    #[tokio::test]
    async fn collection_read_leaves_salted_user_alone() {
        let (core, _) = mock_core(HashMap::new(), "");
        let mut itm = user(1, "alice", "a@e.com");
        itm.set_str("salt", "SALT");
        itm.set_str("password", "H(pw|SALT)");
        let r = collection_read_async(&core, "user", itm).await;
        assert!(!r.should_save);
        assert!(r.item.is_none());
    }

    #[tokio::test]
    async fn collection_read_ignores_other_collections() {
        let (core, _) = mock_core(HashMap::new(), "");
        let r = collection_read_async(&core, "job", Item::new()).await;
        assert!(!r.should_save);
    }

    // -----------------------------------------------------------------------
    // avatars
    // -----------------------------------------------------------------------

    fn write_test_png(path: &Path) {
        let img = image::RgbaImage::from_pixel(4, 4, image::Rgba([255, 0, 0, 255]));
        img.save_with_format(path, image::ImageFormat::Png)
            .expect("write test png");
    }

    fn upload_item(file_path: &str) -> Item {
        let mut files = HashMap::new();
        files.insert("file1".to_string(), file_path.to_string());
        let mut itm = Item::new();
        itm.set_strstr("multipart-files", &files);
        itm
    }

    #[tokio::test]
    async fn get_avatar_requires_auth_and_valid_id() {
        let (core, _) = mock_core(HashMap::new(), "/data");
        assert!(matches!(
            get_avatar_async(&core, &None, "id=1").await,
            WebResponse::Forbidden
        ));
        let u = Some(user(1, "alice", "a@e.com"));
        assert!(matches!(
            get_avatar_async(&core, &u, "").await,
            WebResponse::BadRequest
        ));
        assert!(matches!(
            get_avatar_async(&core, &u, "id=../../etc/passwd").await,
            WebResponse::BadRequest
        ));
        match get_avatar_async(&core, &u, "id=me").await {
            WebResponse::OkFilePath(_, path) => {
                assert_eq!(path, "/data/user-avatars/1.bin");
            }
            _ => panic!("expected OkFilePath"),
        }
    }

    #[tokio::test]
    async fn upload_avatar_rejects_unauthenticated() {
        let dir = tempfile::tempdir().unwrap();
        let (core, _) = mock_core(HashMap::new(), dir.path().to_str().unwrap());
        let src = dir.path().join("upload.png");
        write_test_png(&src);
        // No user, and — the old hole — no `id` parameter at all.
        let r = upload_avatar_async(&core, &None, "", &upload_item(src.to_str().unwrap())).await;
        assert!(matches!(r, WebResponse::Unauthorized));
        assert!(src.exists(), "file must not be consumed before auth");
    }

    #[tokio::test]
    async fn upload_avatar_rejects_foreign_target_for_non_admin() {
        let dir = tempfile::tempdir().unwrap();
        let (core, _) = mock_core(HashMap::new(), dir.path().to_str().unwrap());
        let src = dir.path().join("upload.png");
        write_test_png(&src);
        let u = Some(user(1, "alice", "a@e.com"));
        let r = upload_avatar_async(&core, &u, "id=2", &upload_item(src.to_str().unwrap())).await;
        assert!(matches!(r, WebResponse::Unauthorized));
    }

    #[tokio::test]
    async fn upload_avatar_rejects_malformed_id() {
        let dir = tempfile::tempdir().unwrap();
        let (core, _) = mock_core(HashMap::new(), dir.path().to_str().unwrap());
        let src = dir.path().join("upload.png");
        write_test_png(&src);
        let u = Some(user(1, "alice", "a@e.com"));
        let r = upload_avatar_async(
            &core,
            &u,
            "id=../../../etc/passwd",
            &upload_item(src.to_str().unwrap()),
        )
        .await;
        assert!(matches!(r, WebResponse::BadRequest));
    }

    #[tokio::test]
    async fn upload_avatar_accepts_own_upload() {
        let dir = tempfile::tempdir().unwrap();
        let (core, _) = mock_core(HashMap::new(), dir.path().to_str().unwrap());
        let src = dir.path().join("upload.png");
        write_test_png(&src);
        let u = Some(user(1, "alice", "a@e.com"));
        let r = upload_avatar_async(&core, &u, "id=me", &upload_item(src.to_str().unwrap())).await;
        assert!(matches!(r, WebResponse::Ok));
        let dst = dir.path().join("user-avatars/1.bin");
        assert!(dst.exists());
        // Staging file must be cleaned up.
        assert!(!dir.path().join("user-avatars/1.stage").exists());
        // Result decodes as a PNG again.
        let saved = image::ImageReader::open(&dst)
            .unwrap()
            .with_guessed_format()
            .unwrap()
            .decode()
            .unwrap();
        assert!(saved.width() <= 256 && saved.height() <= 256);
    }

    #[tokio::test]
    async fn upload_avatar_admin_can_set_foreign_avatar() {
        let dir = tempfile::tempdir().unwrap();
        let (core, _) = mock_core(HashMap::new(), dir.path().to_str().unwrap());
        let src = dir.path().join("upload.png");
        write_test_png(&src);
        let u = Some(admin(9, "root", "root@e.com"));
        let r = upload_avatar_async(&core, &u, "id=2", &upload_item(src.to_str().unwrap())).await;
        assert!(matches!(r, WebResponse::Ok));
        assert!(dir.path().join("user-avatars/2.bin").exists());
    }

    #[tokio::test]
    async fn upload_avatar_ignores_malicious_file_name_extension() {
        // The "extension" of the uploaded name contains path separators; the
        // staging path must stay inside user-avatars regardless.
        let dir = tempfile::tempdir().unwrap();
        let (core, _) = mock_core(HashMap::new(), dir.path().to_str().unwrap());
        fs::create_dir_all(dir.path().join("a.b")).unwrap();
        let src = dir.path().join("a.b/../upload");
        write_test_png(&src);
        let u = Some(user(1, "alice", "a@e.com"));
        let r = upload_avatar_async(&core, &u, "id=me", &upload_item(src.to_str().unwrap())).await;
        assert!(matches!(r, WebResponse::Ok));
        assert!(dir.path().join("user-avatars/1.bin").exists());
        // Nothing escaped the avatars directory.
        assert!(!dir.path().join("upload").exists());
    }

    #[tokio::test]
    async fn upload_avatar_rejects_non_image_payload() {
        let dir = tempfile::tempdir().unwrap();
        let (core, _) = mock_core(HashMap::new(), dir.path().to_str().unwrap());
        let src = dir.path().join("payload.png");
        fs::write(&src, b"#!/bin/sh\necho pwned\n").unwrap();
        let u = Some(user(1, "alice", "a@e.com"));
        let r = upload_avatar_async(&core, &u, "id=me", &upload_item(src.to_str().unwrap())).await;
        assert!(matches!(r, WebResponse::BadRequest));
        assert!(!dir.path().join("user-avatars/1.bin").exists());
        assert!(!dir.path().join("user-avatars/1.stage").exists());
    }

    #[tokio::test]
    async fn upload_avatar_rejects_oversized_file() {
        let dir = tempfile::tempdir().unwrap();
        let (core, _) = mock_core(HashMap::new(), dir.path().to_str().unwrap());
        let src = dir.path().join("big.png");
        let f = fs::File::create(&src).unwrap();
        f.set_len(MAX_AVATAR_FILE_BYTES + 1).unwrap();
        drop(f);
        let u = Some(user(1, "alice", "a@e.com"));
        let r = upload_avatar_async(&core, &u, "id=me", &upload_item(src.to_str().unwrap())).await;
        assert!(matches!(r, WebResponse::BadRequest));
        assert!(!dir.path().join("user-avatars/1.stage").exists());
    }

    #[tokio::test]
    async fn upload_avatar_rejects_missing_files() {
        let dir = tempfile::tempdir().unwrap();
        let (core, _) = mock_core(HashMap::new(), dir.path().to_str().unwrap());
        let u = Some(user(1, "alice", "a@e.com"));
        let r = upload_avatar_async(&core, &u, "id=me", &Item::new()).await;
        assert!(matches!(r, WebResponse::BadRequest));
    }

    // -----------------------------------------------------------------------
    // OTP e-mail
    // -----------------------------------------------------------------------

    #[tokio::test]
    async fn otp_email_sent_with_code() {
        let (core, emails) = mock_core(HashMap::new(), "");
        let mut itm = Item::new();
        itm.set_str("email", "alice@example.com");
        itm.set_str("otp", "123456");
        otp_send_email_async(&core, &itm).await;
        // SendEmail is fire-and-forget; a request/reply round-trip through
        // the same ordered channel guarantees it has been processed.
        let _ = core.globals_get_data_path().await;
        let sent = emails.lock().unwrap();
        assert_eq!(sent.len(), 1);
        assert_eq!(sent[0].0, "alice@example.com");
        assert!(sent[0].2.contains("123456"));
    }

    #[tokio::test]
    async fn otp_email_skipped_without_code_or_address() {
        let (core, emails) = mock_core(HashMap::new(), "");
        let mut itm = Item::new();
        itm.set_str("email", "alice@example.com");
        otp_send_email_async(&core, &itm).await;
        let mut itm = Item::new();
        itm.set_str("otp", "123456");
        otp_send_email_async(&core, &itm).await;
        let _ = core.globals_get_data_path().await;
        assert!(emails.lock().unwrap().is_empty());
    }
}
