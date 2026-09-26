package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"time"

	"gopkg.in/yaml.v3"
)

type Contract struct {
	Name       string                 `json:"name"`
	CrossID    string                 `json:"cross_id"`
	Origin     string                 `json:"origin"`
	Version    string                 `json:"version"`
	Capability string                 `json:"capability"`
	Op         string                 `json:"op"`
	Params     map[string]interface{} `json:"params"`
	Expected   map[string]interface{} `json:"expected"`
	Mutant     map[string]interface{} `json:"mutant"`
	SourceKind string                 `json:"source_kind"`
}

type Source struct {
	Contracts []Contract `json:"contracts"`
}

type Eval struct {
	OK     bool                   `json:"ok"`
	Actual map[string]interface{} `json:"actual"`
	Misses []string               `json:"misses"`
}

func scalar(v reflect.Value) (interface{}, bool) {
	if !v.IsValid() {
		return nil, true
	}
	for v.Kind() == reflect.Interface || v.Kind() == reflect.Pointer {
		if v.IsNil() {
			return nil, true
		}
		v = v.Elem()
	}
	if v.CanInterface() {
		if tm, ok := v.Interface().(time.Time); ok {
			if tm.Hour() == 0 && tm.Minute() == 0 && tm.Second() == 0 && tm.Nanosecond() == 0 {
				return tm.Format("2006-01-02"), true
			}
			return tm.Format(time.RFC3339Nano), true
		}
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

func denorm(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		if len(t) == 1 {
			if special, ok := t["special"].(string); ok {
				switch special {
				case "inf":
					return math.Inf(1)
				case "-inf":
					return math.Inf(-1)
				case "nan":
					return math.NaN()
				}
			}
		}
		if pairs, ok := t["__pairs__"].([]interface{}); ok {
			m := map[interface{}]interface{}{}
			for _, pairAny := range pairs {
				pair, ok := pairAny.([]interface{})
				if !ok || len(pair) != 2 {
					continue
				}
				m[denorm(pair[0])] = denorm(pair[1])
			}
			return m
		}
		m := map[string]interface{}{}
		for key, item := range t {
			m[key] = denorm(item)
		}
		return m
	case []interface{}:
		out := make([]interface{}, 0, len(t))
		for _, item := range t {
			out = append(out, denorm(item))
		}
		return out
	case json.Number:
		if i, err := t.Int64(); err == nil {
			return i
		}
		if f, err := strconv.ParseFloat(string(t), 64); err == nil {
			return f
		}
		return string(t)
	default:
		return v
	}
}

func nodeSig(n *yaml.Node, seen map[*yaml.Node]bool) interface{} {
	if n == nil {
		return nil
	}
	if seen[n] {
		return map[string]interface{}{"alias_cycle": true}
	}
	seen[n] = true
	row := map[string]interface{}{
		"kind":         int(n.Kind),
		"style":        int(n.Style),
		"tag":          n.Tag,
		"value":        n.Value,
		"anchor":       n.Anchor,
		"head_comment": n.HeadComment,
		"line_comment": n.LineComment,
		"foot_comment": n.FootComment,
	}
	if len(n.Content) > 0 {
		items := make([]interface{}, 0, len(n.Content))
		for _, child := range n.Content {
			items = append(items, nodeSig(child, seen))
		}
		row["content"] = items
	}
	if n.Alias != nil {
		row["alias"] = nodeSig(n.Alias, seen)
	}
	delete(seen, n)
	return row
}

func run(c Contract, expected map[string]interface{}) map[string]interface{} {
	switch c.Op {
	case "safe_load_json_value", "parse_to_json_docs", "json_parse_success":
		text := str(c.Params["yaml"])
		if c.Op == "json_parse_success" {
			text = str(c.Params["json"])
		}
		values, err := decodeAll(text)
		if err != nil {
			return map[string]interface{}{"error": err.Error()}
		}
		if c.Op == "parse_to_json_docs" {
			return map[string]interface{}{"value": values}
		}
		if len(values) == 1 {
			return map[string]interface{}{"value": values[0]}
		}
		return map[string]interface{}{"value": values}
	case "json_stringify_reparse_success":
		values, err := decodeAll(str(c.Params["json"]))
		if err != nil {
			return map[string]interface{}{"error": err.Error()}
		}
		if len(values) != 1 {
			return map[string]interface{}{"error": "expected one json document"}
		}
		blob, err := json.Marshal(values[0])
		if err != nil {
			return map[string]interface{}{"error": err.Error()}
		}
		again, err := decodeAll(string(blob))
		if err != nil {
			return map[string]interface{}{"error": err.Error()}
		}
		return map[string]interface{}{"value": again[0]}
	case "stringify_reparse_json_docs":
		values, err := decodeAll(str(c.Params["yaml"]))
		if err != nil {
			return map[string]interface{}{"error": err.Error()}
		}
		var rendered bytes.Buffer
		for _, value := range values {
			out, err := yaml.Marshal(denorm(value))
			if err != nil {
				return map[string]interface{}{"error": err.Error()}
			}
			rendered.Write(out)
		}
		again, err := decodeAll(rendered.String())
		if err != nil {
			return map[string]interface{}{"error": err.Error()}
		}
		return map[string]interface{}{"value": again}
	case "emitted_yaml_matches_json":
		values, err := decodeAll(str(c.Params["emitted_yaml"]))
		if err != nil {
			return map[string]interface{}{"error": err.Error()}
		}
		return map[string]interface{}{"value": values}
	case "schema_safe_load_scalar":
		values, err := decodeAll(str(c.Params["yaml"]))
		if err != nil {
			return map[string]interface{}{"error": err.Error()}
		}
		if len(values) != 1 {
			return map[string]interface{}{"error": "expected one scalar"}
		}
		return scalarKind(values[0])
	case "schema_safe_dump_loaded_scalar":
		values, err := decodeAll(str(c.Params["yaml"]))
		if err != nil {
			return map[string]interface{}{"error": err.Error()}
		}
		if len(values) != 1 {
			return map[string]interface{}{"error": "expected one scalar"}
		}
		out, err := yaml.Marshal(denorm(values[0]))
		if err != nil {
			return map[string]interface{}{"error": err.Error()}
		}
		return map[string]interface{}{"dump": stripDump(string(out))}
	case "parse_canonical_equivalence", "compose_canonical_equivalence":
		left, err := decodeAll(str(c.Params["yaml"]))
		if err != nil {
			return map[string]interface{}{"error": err.Error()}
		}
		canonical, _ := expected["canonical"].(string)
		if canonical == "" {
			canonical = str(c.Params["canonical"])
		}
		right, err := decodeAll(canonical)
		if err != nil {
			return map[string]interface{}{"error": err.Error()}
		}
		return map[string]interface{}{"value": equal(left, right)}
	case "emit_parse_roundtrip":
		values, err := decodeAll(str(c.Params["yaml"]))
		if err != nil {
			return map[string]interface{}{"error": err.Error()}
		}
		var rendered bytes.Buffer
		for _, value := range values {
			out, err := yaml.Marshal(denorm(value))
			if err != nil {
				return map[string]interface{}{"error": err.Error()}
			}
			rendered.Write(out)
		}
		again, err := decodeAll(rendered.String())
		if err != nil {
			return map[string]interface{}{"error": err.Error()}
		}
		return map[string]interface{}{"value": equal(values, again)}
	case "load_all_error", "load_single_error":
		_, err := decodeAll(str(c.Params["yaml"]))
		return map[string]interface{}{"error": err != nil, "errors": err != nil}
	case "load_unicode_text", "load_unicode_utf8_bytes", "load_unicode_utf8_bom_bytes", "load_unicode_utf16be_bom_bytes", "load_unicode_utf16le_bom_bytes":
		values, err := decodeAll(str(c.Params["text"]))
		if err != nil {
			return map[string]interface{}{"error": err.Error()}
		}
		if len(values) == 1 {
			return map[string]interface{}{"value": values[0]}
		}
		return map[string]interface{}{"value": values}
	case "scan_tokens", "parse_structure", "cst_roundtrip_source":
		return map[string]interface{}{"error": "nonportable-surface"}
	case "parse_to_value":
		var out interface{}
		err := yaml.Unmarshal([]byte(str(c.Params["yaml"])), &out)
		if err != nil {
			return map[string]interface{}{"error": err.Error()}
		}
		value, ok := norm(out)
		if !ok {
			return map[string]interface{}{"error": "normalize failed"}
		}
		return map[string]interface{}{"value": value}
	case "parse_to_value_at_path":
		var out interface{}
		err := yaml.Unmarshal([]byte(str(c.Params["yaml"])), &out)
		if err != nil {
			return map[string]interface{}{"error": err.Error()}
		}
		value := lookupPath(out, c.Params["path"])
		normalized, ok := norm(value)
		if !ok {
			return map[string]interface{}{"error": "normalize failed"}
		}
		return map[string]interface{}{"value": normalized}
	case "decode_stream_values":
		dec := yaml.NewDecoder(bytes.NewBufferString(str(c.Params["yaml"])))
		var values []interface{}
		for {
			var out interface{}
			err := dec.Decode(&out)
			if err == io.EOF {
				break
			}
			if err != nil {
				return map[string]interface{}{"error": err.Error()}
			}
			values = append(values, out)
		}
		value, ok := norm(values)
		if !ok {
			return map[string]interface{}{"error": "normalize failed"}
		}
		return map[string]interface{}{"value": value}
	case "parse_error_presence":
		var out interface{}
		err := yaml.Unmarshal([]byte(str(c.Params["yaml"])), &out)
		return map[string]interface{}{"errors": err != nil}
	case "marshal_to_yaml":
		out, err := yaml.Marshal(denorm(c.Params["value"]))
		if err != nil {
			return map[string]interface{}{"error": err.Error()}
		}
		return map[string]interface{}{"yaml": string(out)}
	case "parse_node_signature":
		var node yaml.Node
		err := yaml.Unmarshal([]byte(str(c.Params["yaml"])), &node)
		if err != nil {
			return map[string]interface{}{"error": err.Error()}
		}
		return map[string]interface{}{"value": nodeSig(&node, map[*yaml.Node]bool{})}
	default:
		return map[string]interface{}{"error": "unsupported op: " + c.Op}
	}
}

func decodeAll(text string) ([]interface{}, error) {
	dec := yaml.NewDecoder(bytes.NewBufferString(text))
	var values []interface{}
	for {
		var out interface{}
		err := dec.Decode(&out)
		if err == io.EOF {
			break
		}
		if err != nil {
			return nil, err
		}
		value, ok := norm(out)
		if !ok {
			return nil, fmt.Errorf("normalize failed")
		}
		values = append(values, value)
	}
	return values, nil
}

func scalarKind(value interface{}) map[string]interface{} {
	switch v := value.(type) {
	case bool:
		return map[string]interface{}{"kind": "bool", "value": v}
	case nil:
		return map[string]interface{}{"kind": "null", "value": nil}
	case int, int8, int16, int32, int64, uint, uint8, uint16, uint32, uint64:
		return map[string]interface{}{"kind": "int", "value": v}
	case float32, float64:
		f := reflect.ValueOf(v).Convert(reflect.TypeOf(float64(0))).Float()
		if math.IsNaN(f) {
			return map[string]interface{}{"kind": "float", "special": "nan"}
		}
		if math.IsInf(f, 1) {
			return map[string]interface{}{"kind": "float", "special": "inf"}
		}
		if math.IsInf(f, -1) {
			return map[string]interface{}{"kind": "float", "special": "-inf"}
		}
		if math.Trunc(f) == f {
			return map[string]interface{}{"kind": "int", "value": int64(f)}
		}
		return map[string]interface{}{"kind": "float", "value": f}
	case string:
		return map[string]interface{}{"kind": "str", "value": v}
	default:
		return map[string]interface{}{"kind": "str", "value": fmt.Sprint(v)}
	}
}

func stripDump(text string) string {
	if strings.HasSuffix(text, "\n...\n") {
		text = strings.TrimSuffix(text, "\n...\n") + "\n"
	}
	return strings.TrimSuffix(text, "\n")
}

func lookupPath(value interface{}, path interface{}) interface{} {
	steps, ok := path.([]interface{})
	if !ok {
		return value
	}
	current := value
	for _, step := range steps {
		key := fmt.Sprint(step)
		rv := reflect.ValueOf(current)
		for rv.IsValid() && (rv.Kind() == reflect.Interface || rv.Kind() == reflect.Pointer) {
			if rv.IsNil() {
				return nil
			}
			rv = rv.Elem()
		}
		if !rv.IsValid() || rv.Kind() != reflect.Map {
			return nil
		}
		var found reflect.Value
		for _, mapKey := range rv.MapKeys() {
			if fmt.Sprint(mapKey.Interface()) == key {
				found = rv.MapIndex(mapKey)
				break
			}
		}
		if !found.IsValid() {
			return nil
		}
		current = found.Interface()
	}
	return current
}

func str(v interface{}) string {
	if s, ok := v.(string); ok {
		return s
	}
	return fmt.Sprint(v)
}

func canonical(v interface{}) interface{} {
	switch t := v.(type) {
	case map[string]interface{}:
		out := map[string]interface{}{}
		for _, key := range sortedKeys(t) {
			out[key] = canonical(t[key])
		}
		return out
	case []interface{}:
		out := make([]interface{}, 0, len(t))
		for _, item := range t {
			out = append(out, canonical(item))
		}
		return out
	case json.Number:
		return "num:" + string(t)
	case int, int8, int16, int32, int64:
		return "num:" + fmt.Sprintf("%d", t)
	case uint, uint8, uint16, uint32, uint64:
		return "num:" + fmt.Sprintf("%d", t)
	case float32, float64:
		rv := reflect.ValueOf(t)
		f := rv.Convert(reflect.TypeOf(float64(0))).Float()
		if math.IsNaN(f) {
			return "num:nan"
		}
		if math.IsInf(f, 1) {
			return "num:inf"
		}
		if math.IsInf(f, -1) {
			return "num:-inf"
		}
		return "num:" + strconv.FormatFloat(f, 'g', -1, 64)
	default:
		return v
	}
}

func sortedKeys(m map[string]interface{}) []string {
	keys := make([]string, 0, len(m))
	for key := range m {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	return keys
}

func equal(a, b interface{}) bool {
	aj, _ := json.Marshal(canonical(a))
	bj, _ := json.Marshal(canonical(b))
	return string(aj) == string(bj)
}

func evaluate(c Contract, expected map[string]interface{}) Eval {
	actual := run(c, expected)
	if err, ok := actual["error"]; ok {
		return Eval{OK: false, Actual: actual, Misses: []string{fmt.Sprint(err)}}
	}
	for key, value := range expected {
		if key == "error_regex" {
			continue
		}
		if !equal(actual[key], value) {
			return Eval{OK: false, Actual: actual, Misses: []string{fmt.Sprintf("%s mismatch: expected %v, got %v", key, value, actual[key])}}
		}
	}
	return Eval{OK: true, Actual: actual}
}

func main() {
	if len(os.Args) != 2 {
		fmt.Fprintln(os.Stderr, "usage: goyaml-latest-runner <contracts.json>")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var src Source
	dec := json.NewDecoder(bytes.NewReader(data))
	dec.UseNumber()
	if err := dec.Decode(&src); err != nil {
		panic(err)
	}
	type resultRow struct {
		Name           string                 `json:"name"`
		CrossID        string                 `json:"cross_id"`
		Origin         string                 `json:"origin"`
		Version        string                 `json:"version"`
		Capability     string                 `json:"capability"`
		SourceKind     string                 `json:"source_kind"`
		Op             string                 `json:"op"`
		Status         string                 `json:"status"`
		ReplayPassed   bool                   `json:"replay_passed"`
		MutantRejected bool                   `json:"mutant_rejected"`
		Misses         []string               `json:"misses"`
		MutantMisses   []string               `json:"mutant_misses"`
		Actual         map[string]interface{} `json:"actual"`
		MutantActual   map[string]interface{} `json:"mutant_actual"`
	}
	var results []resultRow
	var survivors []Contract
	for _, c := range src.Contracts {
		replay := evaluate(c, c.Expected)
		mutant := Eval{Misses: []string{"mutant not evaluated because replay failed"}}
		if replay.OK {
			mutant = evaluate(c, c.Mutant)
		}
		verified := replay.OK && !mutant.OK
		status := "failed"
		if verified {
			status = "passed"
			survivors = append(survivors, c)
		}
		results = append(results, resultRow{
			Name: c.Name, CrossID: c.CrossID, Origin: c.Origin, Version: c.Version, Capability: c.Capability, SourceKind: c.SourceKind, Op: c.Op,
			Status: status, ReplayPassed: replay.OK, MutantRejected: replay.OK && !mutant.OK,
			Misses: replay.Misses, MutantMisses: mutant.Misses, Actual: replay.Actual, MutantActual: mutant.Actual,
		})
	}
	out := map[string]interface{}{
		"runtime_package":      "gopkg.in/yaml.v3",
		"runtime_version":      "v3.0.1",
		"input_contracts":      len(src.Contracts),
		"latest_replay_passed": count(results, func(row resultRow) bool { return row.ReplayPassed }),
		"latest_replay_failed": count(results, func(row resultRow) bool { return !row.ReplayPassed }),
		"latest_mutant_killed": count(results, func(row resultRow) bool { return row.MutantRejected }),
		"latest_survivors":     len(survivors),
		"survivors":            survivors,
		"results":              results,
	}
	enc := json.NewEncoder(os.Stdout)
	enc.SetIndent("", "  ")
	if err := enc.Encode(out); err != nil {
		panic(err)
	}
}

func count[T any](items []T, pred func(T) bool) int {
	n := 0
	for _, item := range items {
		if pred(item) {
			n++
		}
	}
	return n
}
