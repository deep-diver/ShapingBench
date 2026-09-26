#!/usr/bin/env python3
"""Extract go-yaml/yaml release-history contracts, excluding prior YAML overlap."""

from __future__ import annotations

import io
import json
import re
import subprocess
import tarfile
import tempfile
from collections import Counter
from pathlib import Path
from typing import Any


ROOT = Path(__file__).resolve().parents[2]
REPO = ROOT / ".cache" / "yaml" / "go-yaml"
OUT_DIR = ROOT / "contracts" / "yaml" / "go-yaml"
PY_YAML_SURVIVORS = ROOT / "contracts" / "yaml" / "pyyaml" / "latest_replay_mutant_verified.json"
EEMELI_SURVIVORS = ROOT / "contracts" / "yaml" / "eemeli-yaml" / "latest_replay_mutant_verified.json"

BEGIN = "BEGIN_CONTRACT_DUMP"
END = "END_CONTRACT_DUMP"


DUMPER_TEMPLATE = r'''
package yaml_test

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"reflect"
	"sort"
	"strings"
	"testing"
	"time"

%EXTRA_IMPORTS%
)

type dumpContract struct {
	Name       string                 `json:"name"`
	Capability string                 `json:"capability"`
	Op         string                 `json:"op"`
	Params     map[string]interface{} `json:"params"`
	Expected   map[string]interface{} `json:"expected"`
	SourceKind string                 `json:"source_kind"`
	Source     string                 `json:"source"`
}

func scalar(v reflect.Value) (interface{}, bool) {
	if !v.IsValid() {
		return nil, true
	}
	if v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil, true
		}
		return scalar(v.Elem())
	}
	if v.CanInterface() {
		if tm, ok := v.Interface().(time.Time); ok {
			if tm.Hour() == 0 && tm.Minute() == 0 && tm.Second() == 0 && tm.Nanosecond() == 0 {
				return tm.Format("2006-01-02"), true
			}
			return tm.Format(time.RFC3339Nano), true
		}
	}
	if v.Type().PkgPath() != "" && v.Kind() != reflect.Struct {
		return nil, false
	}
	switch v.Kind() {
	case reflect.Bool:
		return v.Bool(), true
	case reflect.String:
		return v.String(), true
	case reflect.Int, reflect.Int8, reflect.Int16, reflect.Int32, reflect.Int64:
		return v.Int(), true
	case reflect.Uint, reflect.Uint8, reflect.Uint16, reflect.Uint32, reflect.Uint64:
		u := v.Uint()
		if u > uint64(math.MaxInt64) {
			return fmt.Sprintf("%d", u), true
		}
		return int64(u), true
	case reflect.Float32, reflect.Float64:
		f := v.Float()
		if math.IsNaN(f) {
			return map[string]interface{}{"special": "nan"}, true
		}
		if math.IsInf(f, 1) {
			return map[string]interface{}{"special": "inf"}, true
		}
		if math.IsInf(f, -1) {
			return map[string]interface{}{"special": "-inf"}, true
		}
		return f, true
	}
	return nil, false
}

func norm(v interface{}) (interface{}, bool) {
	if v == nil {
		return nil, true
	}
	return normValue(reflect.ValueOf(v))
}

func normValue(v reflect.Value) (interface{}, bool) {
	if !v.IsValid() {
		return nil, true
	}
	for v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil, true
		}
		v = v.Elem()
	}
	if s, ok := scalar(v); ok {
		return s, true
	}
	switch v.Kind() {
	case reflect.Slice, reflect.Array:
		if v.Type().Elem().Kind() == reflect.Uint8 {
			return nil, false
		}
		out := make([]interface{}, 0, v.Len())
		for i := 0; i < v.Len(); i++ {
			item, ok := normValue(v.Index(i))
			if !ok {
				return nil, false
			}
			out = append(out, item)
		}
		return out, true
	case reflect.Map:
		if v.IsNil() {
			return map[string]interface{}{}, true
		}
		keys := v.MapKeys()
		stringKeys := true
		normalizedKeys := make([]string, 0, len(keys))
		normalizedValues := map[string]interface{}{}
		for _, key := range keys {
			k, ok := normValue(key)
			if !ok {
				return nil, false
			}
			ks, ok := k.(string)
			if !ok {
				stringKeys = false
				break
			}
			item, ok := normValue(v.MapIndex(key))
			if !ok {
				return nil, false
			}
			normalizedKeys = append(normalizedKeys, ks)
			normalizedValues[ks] = item
		}
		if stringKeys {
			sort.Strings(normalizedKeys)
			out := map[string]interface{}{}
			for _, key := range normalizedKeys {
				out[key] = normalizedValues[key]
			}
			return out, true
		}
		pairs := make([]interface{}, 0, len(keys))
		for _, key := range keys {
			k, ok := normValue(key)
			if !ok {
				return nil, false
			}
			item, ok := normValue(v.MapIndex(key))
			if !ok {
				return nil, false
			}
			pairs = append(pairs, []interface{}{k, item})
		}
		sort.Slice(pairs, func(i, j int) bool {
			a, _ := json.Marshal(pairs[i])
			b, _ := json.Marshal(pairs[j])
			return string(a) < string(b)
		})
		return map[string]interface{}{"__pairs__": pairs}, true
	}
	return nil, false
}

func genericParseTarget(v interface{}) bool {
	if v == nil {
		return true
	}
	t := reflect.TypeOf(v)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	return strings.Contains(t.String(), "interface {}")
}

func genericEmitTarget(v interface{}) bool {
	if v == nil {
		return true
	}
	if _, ok := norm(v); !ok {
		return false
	}
	t := reflect.TypeOf(v)
	for t.Kind() == reflect.Pointer {
		t = t.Elem()
	}
	if t.PkgPath() == "" {
		if _, ok := scalar(reflect.ValueOf(v)); ok {
			return true
		}
	}
	return strings.Contains(t.String(), "interface {}")
}

func yamlish(s string) bool {
	return !strings.Contains(s, "!!binary") && !strings.Contains(s, "!!python") && !strings.Contains(s, "!!js/")
}

func add(out *[]dumpContract, name, cap, op, sourceKind, source string, params, expected map[string]interface{}) {
	*out = append(*out, dumpContract{Name: name, Capability: cap, Op: op, Params: params, Expected: expected, SourceKind: sourceKind, Source: source})
}

%NODE_SIG%

func TestContractDump(t *testing.T) {
	var out []dumpContract

	for i, item := range unmarshalTests {
		if !yamlish(item.data) || !genericParseTarget(item.value) {
			continue
		}
		value, ok := norm(item.value)
		if !ok {
			continue
		}
		add(&out, fmt.Sprintf("unmarshal_%03d", i), "yaml.parse.value", "parse_to_value", "decode_test.go:unmarshalTests",
			"decode_test.go:unmarshalTests", map[string]interface{}{"yaml": item.data}, map[string]interface{}{"value": value})
	}

%DECODER_BLOCK%

	for i, item := range unmarshalErrorTests {
		if !yamlish(item.data) {
			continue
		}
		add(&out, fmt.Sprintf("unmarshal_error_%03d", i), "yaml.parse.errors", "parse_error_presence", "decode_test.go:unmarshalErrorTests",
			"decode_test.go:unmarshalErrorTests", map[string]interface{}{"yaml": item.data}, map[string]interface{}{"error_regex": item.error, "errors": true})
	}

	add(&out, "unmarshal_nan", "yaml.schema.float", "parse_to_value", "decode_test.go:TestUnmarshalNaN",
		"decode_test.go:TestUnmarshalNaN", map[string]interface{}{"yaml": "notanum: .NaN"}, map[string]interface{}{"value": map[string]interface{}{"notanum": map[string]interface{}{"special": "nan"}}})

%MERGE_BLOCK%

	for i, item := range marshalTests {
		if !yamlish(item.data) || !genericEmitTarget(item.value) {
			continue
		}
		value, ok := norm(item.value)
		if !ok {
			continue
		}
		add(&out, fmt.Sprintf("marshal_%03d", i), "yaml.emit.value", "marshal_to_yaml", "encode_test.go:marshalTests",
			"encode_test.go:marshalTests", map[string]interface{}{"value": value}, map[string]interface{}{"yaml": item.data})
	}

%NODE_BLOCK%

	blob, err := json.Marshal(out)
	if err != nil {
		t.Fatal(err)
	}
	fmt.Println("%BEGIN%")
	os.Stdout.Write(blob)
	fmt.Println()
	fmt.Println("%END%")
}
'''


NODE_BLOCK = r'''
	for i, item := range nodeTests {
		if !yamlish(item.yaml) {
			continue
		}
		testYaml := item.yaml
		if strings.HasPrefix(testYaml, "[encode]") {
			continue
		}
		if strings.HasPrefix(testYaml, "[decode]") {
			testYaml = strings.TrimPrefix(testYaml, "[decode]")
		}
		add(&out, fmt.Sprintf("node_%03d", i), "yaml.compose.node", "parse_node_signature", "node_test.go:nodeTests",
			"node_test.go:nodeTests", map[string]interface{}{"yaml": testYaml}, map[string]interface{}{"value": nodeSig(&item.node)})
	}
'''


NODE_SIG = r'''
func nodeSig(n *yaml.Node) interface{} {
	if n == nil {
		return nil
	}
	row := map[string]interface{}{
		"kind": int(n.Kind),
		"style": int(n.Style),
		"tag": n.Tag,
		"value": n.Value,
		"anchor": n.Anchor,
		"head_comment": n.HeadComment,
		"line_comment": n.LineComment,
		"foot_comment": n.FootComment,
	}
	if len(n.Content) > 0 {
		items := make([]interface{}, 0, len(n.Content))
		for _, child := range n.Content {
			items = append(items, nodeSig(child))
		}
		row["content"] = items
	}
	if n.Alias != nil {
		row["alias"] = nodeSig(n.Alias)
	}
	return row
}
'''


DECODER_BLOCK = r'''
	for i, item := range decoderTests {
		if !yamlish(item.data) {
			continue
		}
		value, ok := norm(item.values)
		if !ok {
			continue
		}
		add(&out, fmt.Sprintf("decoder_%03d", i), "yaml.stream.decode", "decode_stream_values", "decode_test.go:decoderTests",
			"decode_test.go:decoderTests", map[string]interface{}{"yaml": item.data}, map[string]interface{}{"value": value})
	}
'''


MERGE_BLOCK = r'''
	mergeWant := map[string]interface{}{"x": 1, "y": 2, "r": 10, "label": "center/big"}
	for _, key := range []string{"plain", "mergeOne", "mergeMultiple", "override", "shortTag", "longTag", "inlineMap", "inlineSequenceMap"} {
		add(&out, "merge_"+key, "yaml.merge.map", "parse_to_value_at_path", "decode_test.go:mergeTests",
			"decode_test.go:mergeTests", map[string]interface{}{"yaml": mergeTests, "path": []interface{}{key}}, map[string]interface{}{"value": mergeWant})
	}
'''


MERGE_NESTED_BLOCK = r'''
	mergeNestedWant := map[string]interface{}{
		"f": 60,
		"inner": map[string]interface{}{"a": 10},
		"d": 40,
		"e": 50,
		"g": 70,
	}
	add(&out, "merge_nested_outer", "yaml.merge.nested-map", "parse_to_value_at_path", "decode_test.go:mergeTestsNested",
		"decode_test.go:mergeTestsNested", map[string]interface{}{"yaml": mergeTestsNested, "path": []interface{}{"outer"}}, map[string]interface{}{"value": mergeNestedWant})
'''


def semver_key(tag: str) -> tuple[int, int, int, int, str]:
    version = tag.removeprefix("v")
    match = re.match(r"^(\d+)\.(\d+)\.(\d+)(?:-([0-9A-Za-z.-]+))?$", version)
    if not match:
        return (999, 999, 999, 1, tag)
    major, minor, patch = (int(match.group(index)) for index in range(1, 4))
    pre = match.group(4)
    return (major, minor, patch, 0 if pre else 1, pre or "")


def git_tags() -> list[str]:
    output = subprocess.check_output(["git", "-C", str(REPO), "tag", "--list", "v*"], text=True)
    return sorted((line.strip() for line in output.splitlines() if line.strip()), key=semver_key)


def git_show(tag: str, path: str) -> str | None:
    try:
        return subprocess.check_output(
            ["git", "-C", str(REPO), "show", f"{tag}:{path}"],
            text=True,
            stderr=subprocess.DEVNULL,
            errors="surrogateescape",
        )
    except subprocess.CalledProcessError:
        return None


def git_archive(tag: str, target: Path) -> None:
    raw = subprocess.check_output(["git", "-C", str(REPO), "archive", "--format=tar", tag])
    with tarfile.open(fileobj=io.BytesIO(raw), mode="r:") as archive:
        archive.extractall(target, filter="data")


def commit_date(tag: str) -> str:
    return subprocess.check_output(["git", "-C", str(REPO), "log", "-1", "--format=%cI", tag], text=True).strip()


def import_path(tag: str) -> str:
    mod = git_show(tag, "go.mod")
    if mod:
        match = re.search(r"^module\s+(.+)$", mod, re.MULTILINE)
        if match:
            return match.group(1).strip().strip('"')
    return "gopkg.in/yaml.v3" if tag.startswith("v3.") else "gopkg.in/yaml.v2"


def mutate_expected(expected: dict[str, Any]) -> dict[str, Any]:
    mutated = json.loads(json.dumps(expected))
    if "value" in mutated:
        value = mutated["value"]
        if isinstance(value, bool):
            mutated["value"] = not value
        elif isinstance(value, list):
            mutated["value"] = value + ["__mutant__"]
        elif isinstance(value, dict):
            mutated["value"]["__mutant__"] = True
        elif isinstance(value, str):
            mutated["value"] = value + "__mutant__"
        elif isinstance(value, (int, float)):
            mutated["value"] = value + 1
        else:
            mutated["value"] = "__mutant__"
    elif "yaml" in mutated:
        mutated["yaml"] = str(mutated["yaml"]) + "__mutant__"
    elif "errors" in mutated:
        mutated["errors"] = not bool(mutated["errors"])
    else:
        mutated["mutant"] = True
    return mutated


def generic_identity(row: dict[str, Any]) -> str:
    params = row.get("params") or {}
    expected = row.get("expected") or {}
    text = params.get("yaml") or ""
    op = row["op"]
    if op in {"parse_to_value", "parse_to_json_docs", "safe_load_json_value", "schema_safe_load_scalar", "json_parse_success"}:
        return json.dumps(["parse-json", text, expected], sort_keys=True, ensure_ascii=True)
    if op in {"parse_error_presence", "load_all_error", "load_single_error"}:
        return json.dumps(["parse-error", text, expected.get("errors", True)], sort_keys=True, ensure_ascii=True)
    if op in {"marshal_to_yaml", "emitted_yaml_matches_json", "stringify_reparse_json_docs"}:
        return json.dumps([op, params, expected], sort_keys=True, ensure_ascii=True)
    return json.dumps([op, text, expected], sort_keys=True, ensure_ascii=True)


def prior_identities() -> set[str]:
    identities: set[str] = set()
    for path in (PY_YAML_SURVIVORS, EEMELI_SURVIVORS):
        if not path.exists():
            continue
        data = json.loads(path.read_text(encoding="utf-8"))
        identities.update(generic_identity(row) for row in data.get("survivors", []))
    return identities


def identity(row: dict[str, Any]) -> str:
    return json.dumps([row["op"], row["params"], row["expected"]], sort_keys=True, ensure_ascii=True)


def dump_release(tag: str) -> tuple[list[dict[str, Any]], dict[str, Any]]:
    with tempfile.TemporaryDirectory(prefix="goyaml-contract-") as tmp:
        temp = Path(tmp)
        git_archive(tag, temp)
        module = import_path(tag)
        if not (temp / "go.mod").exists():
            (temp / "go.mod").write_text(f"module {module}\n\ngo 1.20\n\nrequire gopkg.in/check.v1 v0.0.0-20161208181325-20d25e280405\n", encoding="utf-8")
        decode_source = (temp / "decode_test.go").read_text(encoding="utf-8", errors="ignore") if (temp / "decode_test.go").exists() else ""
        has_decoder = "var decoderTests" in decode_source
        has_node = (temp / "node_test.go").exists() and "var nodeTests" in (temp / "node_test.go").read_text(encoding="utf-8", errors="ignore")
        merge_block = ""
        if "var mergeTests =" in decode_source:
            merge_block += MERGE_BLOCK
        if "var mergeTestsNested =" in decode_source:
            merge_block += MERGE_NESTED_BLOCK
        dumper = (
            DUMPER_TEMPLATE
            .replace("%IMPORT_PATH%", module)
            .replace("%EXTRA_IMPORTS%", f'\n\tyaml "{module}"' if has_node else "")
            .replace("%DECODER_BLOCK%", DECODER_BLOCK if has_decoder else "")
            .replace("%MERGE_BLOCK%", merge_block)
            .replace("%NODE_SIG%", NODE_SIG if has_node else "")
            .replace("%NODE_BLOCK%", NODE_BLOCK if has_node else "")
            .replace("%BEGIN%", BEGIN)
            .replace("%END%", END)
        )
        (temp / "contract_dump_test.go").write_text(dumper, encoding="utf-8")
        env = {"GOFLAGS": "-mod=mod"}
        try:
            output = subprocess.check_output(
                ["go", "test", "-run", "^TestContractDump$", "-count=1", "-v"],
                cwd=temp,
                text=True,
                stderr=subprocess.STDOUT,
                env={**dict(__import__("os").environ), **env},
                timeout=180,
            )
        except subprocess.CalledProcessError as exc:
            return [], {"tag": tag, "dump_error": exc.output[-4000:], "contracts_seen": 0, "new_contracts": 0}
        except subprocess.TimeoutExpired as exc:
            return [], {"tag": tag, "dump_error": f"timeout: {exc}", "contracts_seen": 0, "new_contracts": 0}
        match = re.search(rf"{BEGIN}\n(.*?)\n{END}", output, re.S)
        if not match:
            return [], {"tag": tag, "dump_error": output[-4000:], "contracts_seen": 0, "new_contracts": 0}
        rows = json.loads(match.group(1))
    contracts = []
    version = tag.removeprefix("v")
    date = commit_date(tag)
    for row in rows:
        contracts.append(
            {
                "name": f"{version}:{row['op']}:{row['name']}",
                "version": version,
                "published_at": date,
                "capability": row["capability"],
                "op": row["op"],
                "params": row["params"],
                "expected": row["expected"],
                "mutant": mutate_expected(row["expected"]),
                "evidence": {"tag": tag, "source": row["source"]},
                "source_kind": row["source_kind"],
            }
        )
    return contracts, {"tag": tag, "version": version, "published_at": date, "contracts_seen": len(contracts), "new_contracts": 0}


def write_rpl(contracts: list[dict[str, Any]], path: Path) -> None:
    lines = []
    for row in contracts:
        lines.append(f"contract {json.dumps(row['name'], ensure_ascii=True)} {{")
        lines.append(f"  version {json.dumps(row['version'], ensure_ascii=True)}")
        lines.append(f"  capability {json.dumps(row['capability'], ensure_ascii=True)}")
        lines.append(f"  op {row['op']}")
        lines.append(f"  params {json.dumps(row['params'], ensure_ascii=True, sort_keys=True)}")
        lines.append(f"  expected {json.dumps(row['expected'], ensure_ascii=True, sort_keys=True)}")
        lines.append("}")
        lines.append("")
    path.write_text("\n".join(lines), encoding="utf-8")


def main() -> int:
    OUT_DIR.mkdir(parents=True, exist_ok=True)
    tags = git_tags()
    prior = prior_identities()
    seen: dict[str, dict[str, Any]] = {}
    release_counts = []
    overlap_skipped = 0
    for tag in tags:
        contracts, audit = dump_release(tag)
        new_count = 0
        for row in contracts:
            if generic_identity(row) in prior:
                overlap_skipped += 1
                continue
            key = identity(row)
            if key not in seen:
                seen[key] = row
                new_count += 1
        audit["new_contracts"] = new_count
        release_counts.append(audit)

    contracts = list(seen.values())
    by_cap = Counter(row["capability"] for row in contracts)
    by_kind = Counter(row["source_kind"] for row in contracts)
    summary = {
        "domain": "YAML Parser/Emitter",
        "project": "go-yaml/yaml",
        "package": "gopkg.in/yaml.v3",
        "latest_version": tags[-1].removeprefix("v") if tags else None,
        "git_tags": len(tags),
        "prior_project_overlap_basis": "yaml/pyyaml + eemeli/yaml latest survivors",
        "prior_overlap_skipped": overlap_skipped,
        "contracts_seen": sum(row.get("contracts_seen", 0) for row in release_counts),
        "extracted_contracts": len(contracts),
        "by_capability": dict(sorted(by_cap.items())),
        "by_source_kind": dict(sorted(by_kind.items())),
        "release_counts": release_counts,
        "contracts": contracts,
    }
    (OUT_DIR / "all_releases_excluding_pyyaml_eemeli.summary.json").write_text(
        json.dumps(summary, ensure_ascii=True, indent=2) + "\n",
        encoding="utf-8",
    )
    write_rpl(contracts, OUT_DIR / "all_releases_excluding_pyyaml_eemeli.rpl")

    lines = [
        "# go-yaml/yaml Release Contract Counts",
        "",
        f"Git tags: {len(tags)}",
        f"Prior PyYAML/eemeli overlap skipped: {overlap_skipped}",
        f"Extracted unique contracts: {len(contracts)}",
        "",
        "| Version | Tag | Seen | New | Dump error |",
        "| --- | --- | ---: | ---: | --- |",
    ]
    for row in release_counts:
        error_lines = (row.get("dump_error") or "").splitlines()
        error = (error_lines[0] if error_lines else "")[:120].replace("|", "\\|")
        lines.append(f"| {row.get('version', '')} | `{row['tag']}` | {row.get('contracts_seen', 0)} | {row.get('new_contracts', 0)} | {error} |")
    (OUT_DIR / "release_contract_counts.md").write_text("\n".join(lines) + "\n", encoding="utf-8")

    audit_lines = [
        "# go-yaml/yaml Extraction Audit",
        "",
        "Scope: language-independent, externally observable YAML parse, stream decode, error, emit, and public node-signature behavior.",
        "",
        "Excluded:",
        "",
        "- Go struct tags, custom marshalers/unmarshalers, time.Duration coercions, net/text interfaces, and other Go-specific data-model behavior.",
        "- Binary byte-slice payloads.",
        "- Contracts with semantic identity already covered by PyYAML or eemeli/yaml latest survivors.",
        "",
        "The extractor compiles each release's own test package in a temporary module and dumps primitive fixture values rather than guessing Go literals textually.",
    ]
    (OUT_DIR / "extraction_audit.md").write_text("\n".join(audit_lines) + "\n", encoding="utf-8")

    printable = {key: summary[key] for key in [
        "latest_version",
        "git_tags",
        "prior_overlap_skipped",
        "contracts_seen",
        "extracted_contracts",
        "by_capability",
        "by_source_kind",
    ]}
    print(json.dumps(printable, ensure_ascii=True, indent=2))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
