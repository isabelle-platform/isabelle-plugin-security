use std::collections::HashMap;
use isabelle_dm::data_model::item::Item;
use isabelle_plugin_api::api::PluginApi;
use log::info;

fn item_list_filter_hook(
    api: &PluginApi,
    user: &Option<Item>,
    collection: &str,
    context: &str,
    map: &mut HashMap<u64, Item>) {
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
pub extern fn register(api: &PluginApi) {
    info!("Registering security");
    (api.route_register_item_list_filter_hook)("security_itm_filter_hook", item_list_filter_hook);
  // ...
}
