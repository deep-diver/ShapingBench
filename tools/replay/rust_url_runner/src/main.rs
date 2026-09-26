use serde::Deserialize;
use serde_json::{json, Map, Value};
use std::io::{self, Read};
use url::{form_urlencoded, Host, Url};

#[derive(Debug, Deserialize)]
struct Contract {
    op: String,
    #[serde(default)]
    params: Value,
}

fn opt_str<'a>(params: &'a Value, key: &str) -> Option<&'a str> {
    params.get(key).and_then(Value::as_str)
}

fn req_str<'a>(params: &'a Value, key: &str) -> Result<&'a str, String> {
    opt_str(params, key).ok_or_else(|| format!("missing string param {key}"))
}

fn url_summary(url: &Url) -> Value {
    json!({
        "href": url.as_str(),
        "scheme": url.scheme(),
        "protocol": url::quirks::protocol(url),
        "username": url.username(),
        "password": url.password().unwrap_or(""),
        "password_opt": url.password(),
        "host": url::quirks::host(url),
        "host_str": url.host_str(),
        "hostname": url::quirks::hostname(url),
        "domain": url.domain(),
        "port": url::quirks::port(url),
        "port_number": url.port(),
        "port_or_known_default": url.port_or_known_default(),
        "path": url.path(),
        "pathname": url::quirks::pathname(url),
        "path_segments": url.path_segments().map(|segments| segments.collect::<Vec<_>>()),
        "query": url.query(),
        "search": url::quirks::search(url),
        "fragment": url.fragment(),
        "hash": url::quirks::hash(url),
        "cannot_be_a_base": url.cannot_be_a_base(),
        "has_authority": url.has_authority(),
        "authority": url.authority(),
        "origin": url.origin().ascii_serialization(),
        "is_special": url.is_special()
    })
}

fn parse_url(params: &Value) -> Result<Value, String> {
    let input = req_str(params, "input")?;
    if let Some(base) = opt_str(params, "base") {
        let base = Url::parse(base).map_err(|e| format!("{e:?}"))?;
        base.join(input)
            .map(|url| url_summary(&url))
            .map_err(|e| format!("{e:?}"))
    } else {
        Url::parse(input)
            .map(|url| url_summary(&url))
            .map_err(|e| format!("{e:?}"))
    }
}

fn parse_failure(params: &Value) -> Value {
    let input = opt_str(params, "input").unwrap_or_default();
    let result = if let Some(base) = opt_str(params, "base") {
        Url::parse(base).and_then(|base| base.join(input))
    } else {
        Url::parse(input)
    };
    match result {
        Ok(url) => json!({"ok": true, "href": url.as_str()}),
        Err(error) => json!({"ok": false, "error": format!("{error:?}")}),
    }
}

fn set_component(params: &Value) -> Result<Value, String> {
    let input = req_str(params, "input")?;
    let component = req_str(params, "component")?;
    let value = opt_str(params, "value").unwrap_or_default();
    let mode = opt_str(params, "mode").unwrap_or("native");
    let mut url = Url::parse(input).map_err(|e| format!("{e:?}"))?;

    let result = if mode == "quirks" {
        match component {
            "href" => url::quirks::set_href(&mut url, value).map_err(|e| format!("{e:?}")),
            "protocol" => url::quirks::set_protocol(&mut url, value).map_err(|_| "()".to_string()),
            "username" => url::quirks::set_username(&mut url, value).map_err(|_| "()".to_string()),
            "password" => url::quirks::set_password(&mut url, value).map_err(|_| "()".to_string()),
            "host" => url::quirks::set_host(&mut url, value).map_err(|_| "()".to_string()),
            "hostname" => url::quirks::set_hostname(&mut url, value).map_err(|_| "()".to_string()),
            "port" => url::quirks::set_port(&mut url, value).map_err(|_| "()".to_string()),
            "pathname" => {
                url::quirks::set_pathname(&mut url, value);
                Ok(())
            }
            "search" => {
                url::quirks::set_search(&mut url, value);
                Ok(())
            }
            "hash" => {
                url::quirks::set_hash(&mut url, value);
                Ok(())
            }
            _ => return Err(format!("unsupported quirks component {component}")),
        }
    } else {
        match component {
            "scheme" => url.set_scheme(value).map_err(|_| "()".to_string()),
            "username" => url.set_username(value).map_err(|_| "()".to_string()),
            "password" => {
                let password = if value.is_empty() { None } else { Some(value) };
                url.set_password(password).map_err(|_| "()".to_string())
            }
            "host" => {
                let host = if value.is_empty() { None } else { Some(value) };
                url.set_host(host).map_err(|e| format!("{e:?}"))
            }
            "port" => {
                let port = if value.is_empty() {
                    None
                } else {
                    Some(value.parse::<u16>().map_err(|e| e.to_string())?)
                };
                url.set_port(port).map_err(|_| "()".to_string())
            }
            "path" => {
                url.set_path(value);
                Ok(())
            }
            "query" => {
                let query = if value.is_empty() { None } else { Some(value) };
                url.set_query(query);
                Ok(())
            }
            "fragment" => {
                let fragment = if value.is_empty() { None } else { Some(value) };
                url.set_fragment(fragment);
                Ok(())
            }
            _ => return Err(format!("unsupported native component {component}")),
        }
    };

    let mut out = match url_summary(&url) {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    out.insert("set_ok".to_string(), json!(result.is_ok()));
    if let Err(error) = result {
        out.insert("set_error".to_string(), json!(error));
    }
    Ok(Value::Object(out))
}

fn join_url(params: &Value) -> Result<Value, String> {
    let base = Url::parse(req_str(params, "base")?).map_err(|e| format!("{e:?}"))?;
    let url = base
        .join(req_str(params, "input")?)
        .map_err(|e| format!("{e:?}"))?;
    Ok(url_summary(&url))
}

fn make_relative(params: &Value) -> Result<Value, String> {
    let base = Url::parse(req_str(params, "base")?).map_err(|e| format!("{e:?}"))?;
    let target = Url::parse(req_str(params, "target")?).map_err(|e| format!("{e:?}"))?;
    Ok(json!({"value": base.make_relative(&target)}))
}

fn query_pairs(params: &Value) -> Result<Value, String> {
    let url = Url::parse(req_str(params, "input")?).map_err(|e| format!("{e:?}"))?;
    let pairs = url
        .query_pairs()
        .map(|(k, v)| vec![k.to_string(), v.to_string()])
        .collect::<Vec<_>>();
    Ok(json!({"pairs": pairs}))
}

fn query_pairs_mut(params: &Value) -> Result<Value, String> {
    let mut url = Url::parse(req_str(params, "input")?).map_err(|e| format!("{e:?}"))?;
    {
        let mut pairs = url.query_pairs_mut();
        for action in params
            .get("actions")
            .and_then(Value::as_array)
            .into_iter()
            .flatten()
        {
            match req_str(action, "type")? {
                "clear" => {
                    pairs.clear();
                }
                "append" => {
                    pairs.append_pair(req_str(action, "name")?, req_str(action, "value")?);
                }
                "extend" => {
                    let items = action
                        .get("pairs")
                        .and_then(Value::as_array)
                        .ok_or("missing pairs")?;
                    for pair in items {
                        let arr = pair.as_array().ok_or("pair must be array")?;
                        pairs.append_pair(
                            arr[0].as_str().unwrap_or_default(),
                            arr[1].as_str().unwrap_or_default(),
                        );
                    }
                }
                _ => return Err("unsupported query_pairs_mut action".to_string()),
            }
        }
    }
    Ok(url_summary(&url))
}

fn path_segments_mut(params: &Value) -> Result<Value, String> {
    let mut url = Url::parse(req_str(params, "input")?).map_err(|e| format!("{e:?}"))?;
    let mut ok = true;
    {
        let segments = url.path_segments_mut();
        match segments {
            Ok(mut segments) => {
                for action in params
                    .get("actions")
                    .and_then(Value::as_array)
                    .into_iter()
                    .flatten()
                {
                    match req_str(action, "type")? {
                        "clear" => {
                            segments.clear();
                        }
                        "push" => {
                            segments.push(req_str(action, "value")?);
                        }
                        "pop" => {
                            segments.pop();
                        }
                        "pop_if_empty" => {
                            segments.pop_if_empty();
                        }
                        _ => return Err("unsupported path_segments_mut action".to_string()),
                    }
                }
            }
            Err(_) => ok = false,
        }
    }
    let mut out = match url_summary(&url) {
        Value::Object(map) => map,
        _ => Map::new(),
    };
    out.insert("mutator_ok".to_string(), json!(ok));
    Ok(Value::Object(out))
}

fn form_urlencoded_serialize(params: &Value) -> Result<Value, String> {
    let mut serializer = form_urlencoded::Serializer::new(String::new());
    let pairs = params
        .get("pairs")
        .and_then(Value::as_array)
        .ok_or("missing pairs")?;
    for pair in pairs {
        let arr = pair.as_array().ok_or("pair must be array")?;
        serializer.append_pair(
            arr[0].as_str().unwrap_or_default(),
            arr[1].as_str().unwrap_or_default(),
        );
    }
    Ok(json!({"value": serializer.finish()}))
}

fn host_parse(params: &Value) -> Result<Value, String> {
    match Host::parse(req_str(params, "input")?) {
        Ok(host) => Ok(json!({"ok": true, "value": host.to_string()})),
        Err(error) => Ok(json!({"ok": false, "error": format!("{error:?}")})),
    }
}

fn domain_convert(params: &Value) -> Result<Value, String> {
    let input = req_str(params, "input")?;
    Ok(json!({
        "ascii": url::quirks::domain_to_ascii(input),
        "unicode": url::quirks::domain_to_unicode(input)
    }))
}

fn origin(params: &Value) -> Result<Value, String> {
    let url = Url::parse(req_str(params, "input")?).map_err(|e| format!("{e:?}"))?;
    Ok(json!({
        "ascii": url.origin().ascii_serialization(),
        "unicode": url.origin().unicode_serialization()
    }))
}

fn parse_with_params(params: &Value) -> Result<Value, String> {
    let input = req_str(params, "input")?;
    let pairs = params
        .get("pairs")
        .and_then(Value::as_array)
        .ok_or("missing pairs")?;
    let pair_vec = pairs
        .iter()
        .map(|pair| {
            let arr = pair.as_array().unwrap();
            (
                arr[0].as_str().unwrap_or_default().to_string(),
                arr[1].as_str().unwrap_or_default().to_string(),
            )
        })
        .collect::<Vec<_>>();
    let url = Url::parse_with_params(input, pair_vec).map_err(|e| format!("{e:?}"))?;
    Ok(url_summary(&url))
}

fn run(contract: &Contract) -> Result<Value, String> {
    match contract.op.as_str() {
        "parse_url" => parse_url(&contract.params),
        "parse_failure" => Ok(parse_failure(&contract.params)),
        "set_component" => set_component(&contract.params),
        "join" => join_url(&contract.params),
        "make_relative" => make_relative(&contract.params),
        "query_pairs" => query_pairs(&contract.params),
        "query_pairs_mut" => query_pairs_mut(&contract.params),
        "path_segments_mut" => path_segments_mut(&contract.params),
        "form_urlencoded_serialize" => form_urlencoded_serialize(&contract.params),
        "host_parse" => host_parse(&contract.params),
        "domain_convert" => domain_convert(&contract.params),
        "origin" => origin(&contract.params),
        "parse_with_params" => parse_with_params(&contract.params),
        _ => Err(format!("unsupported op {}", contract.op)),
    }
}

fn main() {
    let mut input = String::new();
    io::stdin().read_to_string(&mut input).unwrap();
    let output = match serde_json::from_str::<Contract>(&input) {
        Ok(contract) => match run(&contract) {
            Ok(actual) => json!({"ok": true, "actual": actual}),
            Err(error) => json!({"ok": false, "error": error}),
        },
        Err(error) => json!({"ok": false, "error": error.to_string()}),
    };
    println!("{}", serde_json::to_string(&output).unwrap());
}
