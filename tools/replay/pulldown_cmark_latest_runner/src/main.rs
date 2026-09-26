use pulldown_cmark::{html, Options, Parser};
use serde::Deserialize;
use serde_json::{json, Value};
use std::fs;

#[derive(Debug, Deserialize)]
struct Input {
    contracts: Vec<Contract>,
}

#[derive(Debug, Deserialize)]
struct Contract {
    name: String,
    version: String,
    capability: String,
    source_kind: String,
    op: String,
    params: Params,
    expected: Expected,
    mutant: Expected,
}

#[derive(Debug, Deserialize)]
struct Params {
    markdown: String,
    options: Option<OptionsSpec>,
}

#[derive(Debug, Deserialize)]
struct OptionsSpec {
    enabled: Option<Vec<String>>,
}

#[derive(Debug, Deserialize)]
struct Expected {
    html: String,
}

fn html_standardize(input: &str) -> String {
    let normalized = input
        .replace("<br>", "<br />")
        .replace("<br/>", "<br />")
        .replace("<hr>", "<hr />")
        .replace("<hr/>", "<hr />")
        .replace(">\n<", "><");
    html_escape::decode_html_entities(normalized.trim()).to_string()
}

fn options_for(contract: &Contract) -> Options {
    let mut options = Options::empty();
    if contract.capability.contains("tables") {
        options.insert(Options::ENABLE_TABLES);
    }
    if contract.capability.contains("strikethrough") {
        options.insert(Options::ENABLE_STRIKETHROUGH);
    }
    if contract.capability.contains("tasklist") {
        options.insert(Options::ENABLE_TASKLISTS);
    }
    if let Some(spec) = &contract.params.options {
        for name in spec.enabled.as_deref().unwrap_or(&[]) {
            match name.as_str() {
                "tables" => options.insert(Options::ENABLE_TABLES),
                "footnotes" => options.insert(Options::ENABLE_FOOTNOTES),
                "old_footnotes" => options.insert(Options::ENABLE_OLD_FOOTNOTES),
                "strikethrough" => options.insert(Options::ENABLE_STRIKETHROUGH),
                "tasklists" => options.insert(Options::ENABLE_TASKLISTS),
                "smart_punctuation" => options.insert(Options::ENABLE_SMART_PUNCTUATION),
                "heading_attributes" => options.insert(Options::ENABLE_HEADING_ATTRIBUTES),
                "yaml_metadata_blocks" => options.insert(Options::ENABLE_YAML_STYLE_METADATA_BLOCKS),
                "pluses_metadata_blocks" => options.insert(Options::ENABLE_PLUSES_DELIMITED_METADATA_BLOCKS),
                "math" => options.insert(Options::ENABLE_MATH),
                "gfm" => options.insert(Options::ENABLE_GFM),
                "definition_list" => options.insert(Options::ENABLE_DEFINITION_LIST),
                "superscript" => options.insert(Options::ENABLE_SUPERSCRIPT),
                "subscript" => options.insert(Options::ENABLE_SUBSCRIPT),
                "wikilinks" => options.insert(Options::ENABLE_WIKILINKS),
                _ => {}
            }
        }
    }
    options
}

fn evaluate(contract: &Contract, mutant: bool) -> (bool, Value) {
    if contract.op != "render" && contract.op != "render_inline" {
        return (false, json!({"error": format!("unsupported op: {}", contract.op)}));
    }
    let mut actual = String::new();
    let parser = Parser::new_ext(&contract.params.markdown, options_for(contract));
    html::push_html(&mut actual, parser);
    if contract.op == "render_inline" && actual.starts_with("<p>") && actual.ends_with("</p>\n") {
        actual = actual[3..actual.len() - 5].to_string();
    }
    let expected = if mutant { &contract.mutant } else { &contract.expected };
    (
        html_standardize(&actual) == html_standardize(&expected.html),
        json!({"html": actual}),
    )
}

fn main() {
    let path = std::env::args().nth(1).expect("usage: runner contracts.json");
    let input: Input = serde_json::from_str(&fs::read_to_string(path).unwrap()).unwrap();
    let results: Vec<Value> = input
        .contracts
        .iter()
        .map(|contract| {
            let (replay_passed, actual) = evaluate(contract, false);
            let mutant_rejected = replay_passed && !evaluate(contract, true).0;
            json!({
                "name": contract.name,
                "version": contract.version,
                "capability": contract.capability,
                "source_kind": contract.source_kind,
                "op": contract.op,
                "replay_passed": replay_passed,
                "mutant_rejected": mutant_rejected,
                "status": if replay_passed && mutant_rejected { "passed" } else { "failed" },
                "actual": actual
            })
        })
        .collect();
    println!("{}", json!({ "results": results }));
}
