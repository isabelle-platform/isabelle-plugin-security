use isabelle_dm::data_model::item::Item;
use isabelle_dm::data_model::process_result::ProcessResult;
use isabelle_plugin_api::api::PluginApi;
use log::error;
use log::info;
use std::collections::HashMap;

fn secplugin_password_challenge_pre_edit_hook(
    api: &PluginApi,
    user: &Option<Item>,
    collection: &str,
    old_itm: Option<Item>,
    itm: &mut Item,
    del: bool,
    _merge: bool,
) -> ProcessResult {
    let mut salt: String = "<empty salt>".to_string();
    let is_admin = (api.auth_check_role)(&user, "admin");

    if del {
        return ProcessResult {
            succeeded: true,
            error: "".to_string(),
        };
    }

    if collection == "user"
        && old_itm != None
        && (itm.strs.contains_key("password") || itm.strs.contains_key("salt"))
    {
        error!("Can't edit password directly");
        return ProcessResult {
            succeeded: false,
            error: "Can't edit password directly".to_string(),
        };
    }

    if collection == "user" {
        if old_itm.is_none() {
            /* Add salt when creating new user */
            salt = (api.auth_get_new_salt)();
            itm.set_str("salt", &salt);
        } else {
            salt = old_itm.as_ref().unwrap().safe_str("salt", "<empty salt>");
        }
    }

    if collection == "user"
        && old_itm != None
        && itm.strs.contains_key("__password")
        && itm.strs.contains_key("__new_password1")
        && itm.strs.contains_key("__new_password2")
    {
        let old_pw_hash = old_itm.as_ref().unwrap().safe_str("password", "");
        let old_otp = old_itm.as_ref().unwrap().safe_str("otp", "");
        let old_checked_pw = itm.safe_str("__password", "");
        if !is_admin && old_checked_pw == "" {
            error!("Old password is empty");
            return ProcessResult {
                succeeded: false,
                error: "Old password is empty".to_string(),
            };
        }
        let res = is_admin
            || (api.auth_verify_password)(&old_checked_pw, &old_pw_hash)
            || (old_otp != "" && old_otp == old_checked_pw);
        if !res
            || itm.safe_str("__new_password1", "<bad1>")
                != itm.safe_str("__new_password2", "<bad2>")
        {
            error!("Password change challenge failed");
            return ProcessResult {
                succeeded: false,
                error: "Password change challenge failed".to_string(),
            };
        }
        let new_pw = itm.safe_str("__new_password1", "");
        itm.strs.remove("__password");
        itm.strs.remove("__new_password1");
        itm.strs.remove("__new_password2");
        itm.strs.remove("otp");

        let pw_hash = (api.auth_get_password_hash)(&new_pw, &salt);
        if itm.strs.contains_key("otp") {
            itm.strs.remove("otp");
        }
        itm.set_str("password", &pw_hash);
    }
    return ProcessResult {
        succeeded: true,
        error: "".to_string(),
    };
}

fn secplugin_check_unique_login_email(
    api: &PluginApi,
    _user: &Option<Item>,
    _collection: &str,
    _old_itm: Option<Item>,
    itm: &mut Item,
    del: bool,
    merge: bool,
) -> ProcessResult {
    let mut itm_upd = if _old_itm != None {
        _old_itm.unwrap()
    } else {
        Item::new()
    };
    if merge {
        itm_upd.merge(itm);
    } else {
        itm_upd = itm.clone();
    }
    if del {
        return ProcessResult {
            succeeded: true,
            error: "".to_string(),
        };
    }
    let email = itm_upd.safe_str("email", "").to_lowercase();
    let login = itm.safe_str("login", "").to_lowercase();

    if email == "" {
        return ProcessResult {
            succeeded: false,
            error: "E-Mail must not be empty".to_string(),
        };
    }

    let users = (api.db_get_all_items)("user", "id", "");
    for usr in &users.map {
        if *usr.0 != itm.id {
            if login != "" && login == usr.1.safe_str("login", "").to_lowercase() {
                return ProcessResult {
                    succeeded: false,
                    error: "Login mustn't match already existing one".to_string(),
                };
            }
            if email == usr.1.safe_str("email", "").to_lowercase() {
                return ProcessResult {
                    succeeded: false,
                    error: "E-Mail mustn't match already existing one".to_string(),
                };
            }
        }
    }

    return ProcessResult {
        succeeded: true,
        error: "".to_string(),
    };
}

fn secplugin_otp_send_email(api: &PluginApi, itm: &Item) {
    let email = itm.safe_str("email", "");
    let otp = itm.safe_str("otp", "");
    if email == "" || otp == "" {
        return;
    }

    (api.fn_send_email)(
        &email,
        "Your login code",
        &format!("Enter this as password: {}", otp),
    );
}

fn secplugin_collection_read_hook(api: &PluginApi, collection: &str, itm: &mut Item) -> bool {
    if collection == "user" {
        if !itm.strs.contains_key("salt") {
            let salt = (api.auth_get_new_salt)();
            itm.set_str("salt", &salt);
            info!("There is no salt for user {}, created new", itm.id);
            if itm.strs.contains_key("password") {
                let pw_old = itm.safe_str("password", "");
                let hash = (api.auth_get_password_hash)(&pw_old, &salt);
                itm.set_str("password", &hash);
                info!("Rehashed password for user {}", itm.id);
            }
            return true;
        }
    }
    return false;
}

fn secplugin_item_list_filter_hook(
    api: &PluginApi,
    user: &Option<Item>,
    collection: &str,
    context: &str,
    map: &mut HashMap<u64, Item>,
) {
    let mut list = true;
    let is_admin = (api.auth_check_role)(&user, "admin");

    if is_admin && collection != "user" {
        return;
    }

    if context == "full" {
        list = false;
    }

    let mut short_map: HashMap<u64, Item> = HashMap::new();
    if user.is_none() {
        *map = short_map;
        return;
    }

    info!(
        "Checking collection {} user id {}",
        collection,
        user.as_ref().unwrap().id
    );
    if list {
        for el in &mut *map {
            if collection == "user" {
                if *el.0 == user.as_ref().unwrap().id || is_admin {
                    let mut itm = Item::new();
                    itm.id = *el.0;
                    itm.strs
                        .insert("name".to_string(), el.1.safe_str("name", ""));
                    if *el.0 == user.as_ref().unwrap().id || is_admin {
                        itm.strs
                            .insert("phone".to_string(), el.1.safe_str("phone", ""));
                        itm.bools.insert(
                            "has_insurance".to_string(),
                            el.1.safe_bool("has_insurance", false),
                        );
                    }
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
            } else {
                let mut itm = Item::new();
                itm.id = *el.0;
                itm.strs
                    .insert("name".to_string(), el.1.safe_str("name", ""));
                if el.1.strs.contains_key("customer") {
                    itm.strs
                        .insert("customer".to_string(), el.1.safe_str("customer", ""));
                }
                if el.1.strs.contains_key("ticket_ref") {
                    itm.strs
                        .insert("ticket_ref".to_string(), el.1.safe_str("ticket_ref", ""));
                }
                short_map.insert(*el.0, itm);
            }
        }
    } else {
        if collection == "user" {
            for el in &mut *map {
                if *el.0 != user.as_ref().unwrap().id && !is_admin {
                    /* nothing */
                } else {
                    let mut itm = el.1.clone();
                    if itm.strs.contains_key("salt") {
                        itm.strs.remove("salt");
                    }
                    if itm.strs.contains_key("password") {
                        itm.strs.remove("password");
                    }
                    short_map.insert(*el.0, itm);
                }
            }
        } else {
            short_map = map.clone();
        }
    }
    *map = short_map;
}

#[no_mangle]
pub extern "C" fn register(api: &PluginApi) {
    info!("Registering security");
    (api.route_register_item_list_filter_hook)(
        "security_itm_filter_hook",
        secplugin_item_list_filter_hook,
    );
    (api.route_register_collection_read_hook)(
        "security_collection_read_hook",
        secplugin_collection_read_hook,
    );
    (api.route_register_call_otp_hook)("security_otp_send_email", secplugin_otp_send_email);
    (api.route_register_item_pre_edit_hook)(
        "security_check_unique_login_email",
        secplugin_check_unique_login_email,
    );
    (api.route_register_item_pre_edit_hook)(
        "security_password_challenge_pre_edit_hook",
        secplugin_password_challenge_pre_edit_hook,
    );
}
