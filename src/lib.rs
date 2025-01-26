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
use isabelle_dm::data_model::data_object_action::DataObjectAction;
use isabelle_dm::data_model::item::Item;
use isabelle_dm::data_model::process_result::ProcessResult;
use isabelle_plugin_api::api::*;
use log::error;
use log::info;
use std::collections::HashMap;

struct SecurityPlugin {}

impl SecurityPlugin {
    fn check_unique_login_email(
        &mut self,
        api: &Box<dyn PluginApi>,
        _user: &Option<Item>,
        _collection: &str,
        _old_itm: Option<Item>,
        itm: &mut Item,
        action: DataObjectAction,
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
        if action == DataObjectAction::Delete {
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

        let users = api.db_get_all_items("user", "id", "");
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

    fn challenge_pre_edit_hook(
        &mut self,
        api: &Box<dyn PluginApi>,
        user: &Option<Item>,
        collection: &str,
        old_itm: Option<Item>,
        itm: &mut Item,
        action: DataObjectAction,
        _merge: bool,
    ) -> ProcessResult {
        let mut salt: String = "<empty salt>".to_string();
        let is_admin = api.auth_check_role(&user, "admin");

        if action == DataObjectAction::Delete {
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
                salt = api.auth_get_new_salt();
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
                || (old_pw_hash != "" && api.auth_verify_password(&old_checked_pw, &old_pw_hash))
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

            let pw_hash = api.auth_get_password_hash(&new_pw, &salt);
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
}
impl Plugin for SecurityPlugin {
    fn ping_test(&mut self) {}

    fn item_pre_edit_hook(
        &mut self,
        api: &Box<dyn PluginApi>,
        hndl: &str,
        user: &Option<Item>,
        collection: &str,
        old_itm: Option<Item>,
        itm: &mut Item,
        action: DataObjectAction,
        _merge: bool,
    ) -> ProcessResult {
        if hndl == "security_password_challenge_pre_edit_hook" {
            return self.challenge_pre_edit_hook(
                api,
                user,
                collection,
                old_itm.clone(),
                itm,
                action,
                _merge,
            );
        }

        if hndl == "security_check_unique_login_email" {
            return self
                .check_unique_login_email(api, user, collection, old_itm, itm, action, _merge);
        }

        return ProcessResult {
            succeeded: false,
            error: "not implemented".to_string(),
        };
    }

    fn item_post_edit_hook(
        &mut self,
        _api: &Box<dyn PluginApi>,
        _hndl: &str,
        _: &str,
        _: Option<Item>,
        _: u64,
        _: DataObjectAction,
    ) {
    }

    fn item_auth_hook(
        &mut self,
        _api: &Box<dyn PluginApi>,
        _hndl: &str,
        _: &Option<Item>,
        _: &str,
        _: u64,
        _: Option<Item>,
        _: bool,
    ) -> bool {
        return true;
    }

    fn item_list_filter_hook(
        &mut self,
        api: &Box<dyn PluginApi>,
        hndl: &str,
        user: &Option<Item>,
        collection: &str,
        context: &str,
        map: &mut HashMap<u64, Item>,
    ) {
        if hndl != "security_itm_filter_hook" {
            return;
        }

        let mut list = true;
        let is_admin = api.auth_check_role(&user, "admin");

        if collection != "user" {
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
                if *el.0 == user.as_ref().unwrap().id || is_admin ||
                   el.1.safe_bool("__security_preserve", false) {
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
            for el in &mut *map {
                if *el.0 != user.as_ref().unwrap().id &&
                   !is_admin &&
                   !el.1.safe_bool("__security_preserve", false) {
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
        }
        *map = short_map;
    }

    fn route_url_hook(
        &mut self,
        _api: &Box<dyn PluginApi>,
        _hndl: &str,
        _: &Option<Item>,
        _: &str,
    ) -> WebResponse {
        return WebResponse::NotImplemented;
    }

    fn route_unprotected_url_hook(
        &mut self,
        _api: &Box<dyn PluginApi>,
        _hndl: &str,
        _: &Option<Item>,
        _: &str,
    ) -> WebResponse {
        return WebResponse::NotImplemented;
    }

    fn route_unprotected_url_post_hook(
        &mut self,
        _api: &Box<dyn PluginApi>,
        _hndl: &str,
        _: &Option<Item>,
        _: &str,
        _: &Item,
    ) -> WebResponse {
        return WebResponse::NotImplemented;
    }

    fn collection_read_hook(
        &mut self,
        api: &Box<dyn PluginApi>,
        hndl: &str,
        collection: &str,
        itm: &mut Item,
    ) -> bool {
        if hndl != "security_collection_read_hook" {
            return false;
        }
        if collection == "user" {
            if !itm.strs.contains_key("salt") {
                let salt = api.auth_get_new_salt();
                itm.set_str("salt", &salt);
                info!("There is no salt for user {}, created new", itm.id);
                if itm.strs.contains_key("password") {
                    let pw_old = itm.safe_str("password", "");
                    let hash = api.auth_get_password_hash(&pw_old, &salt);
                    itm.set_str("password", &hash);
                    info!("Rehashed password for user {}", itm.id);
                }
                return true;
            }
        }
        return false;
    }

    fn call_otp_hook(&mut self, api: &Box<dyn PluginApi>, hndl: &str, itm: &Item) {
        if hndl != "security_otp_send_email" {
            return;
        }

        let email = itm.safe_str("email", "");
        let otp = itm.safe_str("otp", "");
        if email == "" || otp == "" {
            return;
        }

        api.fn_send_email(
            &email,
            "Your login code",
            &format!("Enter this as password: {}", otp),
        );
    }
}

#[no_mangle]
pub fn register(api: &mut dyn PluginPoolApi) {
    api.register(Box::new(SecurityPlugin {}));
}
