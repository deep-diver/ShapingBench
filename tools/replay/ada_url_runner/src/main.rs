use ada_url::{HostType, Idna, SchemeType, Url, UrlSearchParams};
use serde_json::{Value, json};
use std::io::{self, Read};

fn s<'a>(value: &'a Value, key: &str) -> Option<&'a str> {
    value.get(key).and_then(Value::as_str)
}

fn arr<'a>(value: &'a Value, key: &str) -> Vec<&'a Value> {
    value
        .get(key)
        .and_then(Value::as_array)
        .map(|items| items.iter().collect())
        .unwrap_or_default()
}

fn host_type_name(value: HostType) -> &'static str {
    match value {
        HostType::Domain => "Domain",
        HostType::IPV4 => "IPV4",
        HostType::IPV6 => "IPV6",
    }
}

fn scheme_type_name(value: SchemeType) -> &'static str {
    match value {
        SchemeType::Http => "Http",
        SchemeType::NotSpecial => "NotSpecial",
        SchemeType::Https => "Https",
        SchemeType::Ws => "Ws",
        SchemeType::Ftp => "Ftp",
        SchemeType::Wss => "Wss",
        SchemeType::File => "File",
    }
}

fn url_props(url: &Url) -> Value {
    let c = url.components();
    json!({
        "href": url.href(),
        "as_str": url.as_str(),
        "origin": url.origin(),
        "protocol": url.protocol(),
        "username": url.username(),
        "password": url.password(),
        "host": url.host(),
        "hostname": url.hostname(),
        "port": url.port(),
        "pathname": url.pathname(),
        "search": url.search(),
        "hash": url.hash(),
        "host_type": host_type_name(url.host_type()),
        "scheme_type": scheme_type_name(url.scheme_type()),
        "has_credentials": url.has_credentials(),
        "has_empty_hostname": url.has_empty_hostname(),
        "has_hostname": url.has_hostname(),
        "has_non_empty_username": url.has_non_empty_username(),
        "has_non_empty_password": url.has_non_empty_password(),
        "has_password": url.has_password(),
        "has_port": url.has_port(),
        "has_search": url.has_search(),
        "has_hash": url.has_hash(),
        "components": {
            "protocol_end": c.protocol_end,
            "username_end": c.username_end,
            "host_start": c.host_start,
            "host_end": c.host_end,
            "port": c.port,
            "pathname_start": c.pathname_start,
            "search_start": c.search_start,
            "hash_start": c.hash_start
        }
    })
}

fn parse_url(params: &Value) -> Value {
    let input = s(params, "input").unwrap_or("");
    let base = s(params, "base");
    match Url::parse(input, base) {
        Ok(url) => json!({"ok": true, "result": url_props(&url)}),
        Err(err) => json!({"ok": false, "throws": "ParseUrlError", "message": err.to_string()}),
    }
}

fn can_parse(params: &Value) -> Value {
    let input = s(params, "input").unwrap_or("");
    let base = s(params, "base");
    json!({"ok": true, "result": {"value": Url::can_parse(input, base)}})
}

fn set_component(params: &Value) -> Value {
    let input = s(params, "input").unwrap_or("");
    let base = s(params, "base");
    let mut url = match Url::parse(input, base) {
        Ok(url) => url,
        Err(err) => {
            return json!({"ok": false, "throws": "ParseUrlError", "message": err.to_string()});
        }
    };
    let component = s(params, "component").unwrap_or("");
    let value = s(params, "value");
    let setter_ok = match component {
        "href" => url.set_href(value.unwrap_or("")).is_ok(),
        "protocol" => url.set_protocol(value.unwrap_or("")).is_ok(),
        "username" => url.set_username(value).is_ok(),
        "password" => url.set_password(value).is_ok(),
        "host" => url.set_host(value).is_ok(),
        "hostname" => url.set_hostname(value).is_ok(),
        "port" => url.set_port(value).is_ok(),
        "pathname" => url.set_pathname(value).is_ok(),
        "search" => {
            url.set_search(value);
            true
        }
        "hash" => {
            url.set_hash(value);
            true
        }
        _ => return json!({"ok": false, "throws": "UnsupportedComponent", "message": component}),
    };
    json!({"ok": true, "result": {"setter_ok": setter_ok, "url": url_props(&url)}})
}

fn search_params_view(params: &Value) -> Value {
    let input = s(params, "input").unwrap_or("");
    let mut sp = match UrlSearchParams::parse(input) {
        Ok(sp) => sp,
        Err(err) => {
            return json!({"ok": false, "throws": "ParseUrlError", "message": err.to_string()});
        }
    };
    for action in arr(params, "actions") {
        let action_type = s(action, "type").unwrap_or("");
        match action_type {
            "append" => sp.append(
                s(action, "key").unwrap_or(""),
                s(action, "value").unwrap_or(""),
            ),
            "set" => sp.set(
                s(action, "key").unwrap_or(""),
                s(action, "value").unwrap_or(""),
            ),
            "remove_key" => sp.remove_key(s(action, "key").unwrap_or("")),
            "remove" => sp.remove(
                s(action, "key").unwrap_or(""),
                s(action, "value").unwrap_or(""),
            ),
            "sort" => sp.sort(),
            _ => {
                return json!({"ok": false, "throws": "UnsupportedSearchParamsAction", "message": action_type});
            }
        }
    }
    let probe = s(params, "probe").unwrap_or("");
    let probe_values_view = sp.get_all(probe);
    let mut probe_values = Vec::with_capacity(probe_values_view.len());
    for index in 0..probe_values_view.len() {
        if let Some(item) = probe_values_view.get(index) {
            probe_values.push(item.to_string());
        }
    }
    json!({
        "ok": true,
        "result": {
            "len": sp.len(),
            "is_empty": sp.is_empty(),
            "string": sp.to_string(),
            "contains_probe_key": sp.contains_key(probe),
            "probe_value": sp.get(probe),
            "probe_values": probe_values,
            "keys": sp.keys().collect::<Vec<_>>(),
            "values": sp.values().collect::<Vec<_>>(),
            "entries": sp.entries().map(|(k, v)| vec![k, v]).collect::<Vec<_>>()
        }
    })
}

fn compare(params: &Value) -> Value {
    let left = Url::parse(s(params, "left").unwrap_or(""), None);
    let right = Url::parse(s(params, "right").unwrap_or(""), None);
    match (left, right) {
        (Ok(left), Ok(right)) => json!({"ok": true, "result": {
            "eq": left == right,
            "lt": left < right,
            "left": left.href(),
            "right": right.href()
        }}),
        _ => json!({"ok": false, "throws": "ParseUrlError"}),
    }
}

fn idna(params: &Value) -> Value {
    let input = s(params, "input").unwrap_or("");
    let mode = s(params, "mode").unwrap_or("");
    let value = match mode {
        "ascii" => Idna::ascii(input),
        "unicode" => Idna::unicode(input),
        _ => return json!({"ok": false, "throws": "UnsupportedIdnaMode", "message": mode}),
    };
    json!({"ok": true, "result": {"value": value}})
}

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let contract: Value = serde_json::from_str(&input).unwrap();
    let op = s(&contract, "op").unwrap_or("");
    let params = contract.get("params").unwrap_or(&Value::Null);
    let result = match op {
        "parse" => parse_url(params),
        "can_parse" => can_parse(params),
        "set_component" => set_component(params),
        "search_params" => search_params_view(params),
        "compare" => compare(params),
        "idna" => idna(params),
        _ => json!({"ok": false, "throws": "UnsupportedOp", "message": op}),
    };
    println!("{}", serde_json::to_string(&result).unwrap());
}
