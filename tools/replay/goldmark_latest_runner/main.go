package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	stdhtml "html"
	"os"
	"regexp"
	"strings"

	"github.com/yuin/goldmark/v2/ast"
	"github.com/yuin/goldmark/v2/extension"
	"github.com/yuin/goldmark/v2/parser"
	"github.com/yuin/goldmark/v2/renderer/html"
	"github.com/yuin/goldmark/v2/text"
	"github.com/yuin/goldmark/v2/util"
)

type Input struct {
	Contracts []Contract `json:"contracts"`
}

type Contract struct {
	Name       string   `json:"name"`
	Version    string   `json:"version"`
	Capability string   `json:"capability"`
	SourceKind string   `json:"source_kind"`
	Op         string   `json:"op"`
	Params     Params   `json:"params"`
	Expected   Expected `json:"expected"`
	Mutant     Expected `json:"mutant"`
}

type Params struct {
	Markdown string      `json:"markdown"`
	Options  OptionsSpec `json:"options"`
}

type OptionsSpec struct {
	Enabled           []string `json:"enabled"`
	XHTML             bool     `json:"xhtml"`
	Unsafe            bool     `json:"unsafe"`
	HardWraps         bool     `json:"hard_wraps"`
	EscapedSpace      bool     `json:"escaped_space"`
	LineBreakStrategy string   `json:"line_break_strategy"`
	Attribute         bool     `json:"attribute"`
	AutoHeadingID     bool     `json:"auto_heading_id"`
	TableAlignMethod  string   `json:"table_align_method"`
	LinkifyMode       string   `json:"linkify_mode"`
	FootnoteMode      string   `json:"footnote_mode"`
	CustomIDGenerator string   `json:"custom_id_generator"`
}

type Expected struct {
	HTML string `json:"html"`
}

type fixedIDGenerator struct {
	value string
}

func (g *fixedIDGenerator) Generate(_ []byte, _ ast.NodeKind) []byte {
	return []byte(g.value)
}

type footnotePrefix struct{}

func (a *footnotePrefix) Transform(node *ast.Document, _ text.Reader, _ parser.Context) {
	node.Metadata()["footnote-prefix"] = "article12-"
}

func htmlStandardize(input string) string {
	out := strings.ReplaceAll(input, "<br>", "<br />")
	out = strings.ReplaceAll(out, "<br/>", "<br />")
	out = strings.ReplaceAll(out, "<hr>", "<hr />")
	out = strings.ReplaceAll(out, "<hr/>", "<hr />")
	out = strings.ReplaceAll(out, ">\n<", "><")
	return stdhtml.UnescapeString(strings.TrimSpace(out))
}

func contains(xs []string, name string) bool {
	for _, x := range xs {
		if x == name {
			return true
		}
	}
	return false
}

func build(spec OptionsSpec, capability string) (parser.Parser, html.Renderer) {
	parserOptions := []parser.Option{}
	rendererOptions := []html.Option{}
	htmlExtensions := []html.Extension{}
	parserExtensions := []parser.Extension{}

	if spec.Attribute {
		parserOptions = append(parserOptions, parser.WithAttribute())
	}
	if spec.AutoHeadingID {
		parserOptions = append(parserOptions, parser.WithAutoHeadingID())
	}
	if spec.EscapedSpace {
		parserOptions = append(parserOptions, parser.WithEscapedSpace())
	}
	if spec.CustomIDGenerator != "" {
		parserOptions = append(parserOptions, parser.WithIDGenerator(&fixedIDGenerator{value: spec.CustomIDGenerator}))
	}

	if spec.XHTML {
		rendererOptions = append(rendererOptions, html.WithXHTML())
	}
	if spec.Unsafe {
		rendererOptions = append(rendererOptions, html.WithUnsafe())
	}
	if spec.HardWraps {
		rendererOptions = append(rendererOptions, html.WithHardWraps())
	}
	switch spec.LineBreakStrategy {
	case "simple_east_asian":
		rendererOptions = append(rendererOptions, html.WithLineBreakStrategy(html.SimpleEastAsianLineBreakStrategy))
	case "css_text3":
		rendererOptions = append(rendererOptions, html.WithLineBreakStrategy(html.CSSText3LineBreakStrategy))
	}

	if contains(spec.Enabled, "tables") || strings.Contains(capability, "tables") {
		tableOptions := []extension.TableHTMLRendererOption{}
		switch spec.TableAlignMethod {
		case "attribute":
			tableOptions = append(tableOptions, extension.WithTableCellAlignMethod(extension.TableCellAlignAttribute))
		case "style":
			tableOptions = append(tableOptions, extension.WithTableCellAlignMethod(extension.TableCellAlignStyle))
		case "default":
			tableOptions = append(tableOptions, extension.WithTableCellAlignMethod(extension.TableCellAlignDefault))
		case "none":
			tableOptions = append(tableOptions, extension.WithTableCellAlignMethod(extension.TableCellAlignNone))
		}
		parserExtensions = append(parserExtensions, extension.NewTableParser())
		htmlExtensions = append(htmlExtensions, extension.NewTableHTMLRenderer(tableOptions...))
	}
	if contains(spec.Enabled, "footnotes") || strings.Contains(capability, "footnotes") {
		footnoteOptions := []extension.FootnoteHTMLRendererOption{}
		if spec.FootnoteMode == "article12_custom" {
			footnoteOptions = append(footnoteOptions,
				extension.WithIDPrefix("article12-"),
				extension.WithLinkClass("link-class"),
				extension.WithBacklinkClass("backlink-class"),
				extension.WithLinkTitle("link-title-%%-^^"),
				extension.WithBacklinkTitle("backlink-title"),
				extension.WithBacklinkHTML("^"),
			)
			parserOptions = append(parserOptions, parser.WithASTTransformers(
				util.Prioritized[parser.ASTTransformer](&footnotePrefix{}, 100),
			))
		}
		parserExtensions = append(parserExtensions, extension.NewFootnoteParser())
		htmlExtensions = append(htmlExtensions, extension.NewFootnoteHTMLRenderer(footnoteOptions...))
	}
	if contains(spec.Enabled, "strikethrough") || strings.Contains(capability, "strikethrough") {
		parserExtensions = append(parserExtensions, extension.NewStrikethroughParser())
		htmlExtensions = append(htmlExtensions, extension.NewStrikethroughHTMLRenderer())
	}
	if contains(spec.Enabled, "tasklists") || strings.Contains(capability, "tasklists") {
		parserExtensions = append(parserExtensions, extension.NewTaskListItemParser())
		htmlExtensions = append(htmlExtensions, extension.NewTaskListItemHTMLRenderer())
	}
	if contains(spec.Enabled, "typographer") || contains(spec.Enabled, "smart_punctuation") || strings.Contains(capability, "typographer") || strings.Contains(capability, "smartquotes") {
		parserExtensions = append(parserExtensions, extension.NewTypographerParser())
	}
	if contains(spec.Enabled, "definition_list") || strings.Contains(capability, "definition") {
		parserExtensions = append(parserExtensions, extension.NewDefinitionListParser())
		htmlExtensions = append(htmlExtensions, extension.NewDefinitionListHTMLRenderer())
	}
	if contains(spec.Enabled, "linkify") || strings.Contains(capability, "linkify") {
		linkOptions := []extension.LinkifyParserOption{}
		switch spec.LinkifyMode {
		case "allowed_ssh_url_regexp":
			linkOptions = append(linkOptions,
				extension.WithAllowedProtocols([]string{"ssh:"}),
				extension.WithURLRegexp(regexp.MustCompile(`\w+://[^\s]+`)),
			)
		case "www_example_only":
			linkOptions = append(linkOptions, extension.WithWWWRegexp(regexp.MustCompile(`www\.example\.com`)))
		case "email_user_only":
			linkOptions = append(linkOptions, extension.WithEmailRegexp(regexp.MustCompile(`user@example\.com`)))
		}
		parserExtensions = append(parserExtensions, extension.NewLinkifyParser(linkOptions...))
	}
	if len(parserExtensions) > 0 {
		parserOptions = append(parserOptions, parser.WithExtensions(parserExtensions...))
	}
	if len(htmlExtensions) > 0 {
		rendererOptions = append(rendererOptions, html.WithExtensions(htmlExtensions...))
	}
	return parser.New(parserOptions...), html.New(rendererOptions...)
}

func render(markdown string, spec OptionsSpec, capability string, inline bool) (string, error) {
	p, r := build(spec, capability)
	var buf bytes.Buffer
	source := []byte(markdown)
	doc := p.Parse(source)
	if err := r.Render(&buf, source, doc); err != nil {
		return "", err
	}
	out := buf.String()
	if inline && strings.HasPrefix(out, "<p>") && strings.HasSuffix(out, "</p>\n") {
		out = strings.TrimSuffix(strings.TrimPrefix(out, "<p>"), "</p>\n")
	}
	return out, nil
}

func evaluate(contract Contract, mutant bool) (bool, map[string]any) {
	if contract.Op != "render" && contract.Op != "render_inline" {
		return false, map[string]any{"error": "unsupported op: " + contract.Op}
	}
	actual, err := render(contract.Params.Markdown, contract.Params.Options, contract.Capability, contract.Op == "render_inline")
	if err != nil {
		return false, map[string]any{"error": err.Error()}
	}
	expected := contract.Expected.HTML
	if mutant {
		expected = contract.Mutant.HTML
	}
	return htmlStandardize(actual) == htmlStandardize(expected), map[string]any{"html": actual}
}

func main() {
	if len(os.Args) != 2 {
		_, _ = fmt.Fprintln(os.Stderr, "usage: goldmark-runner contracts.json")
		os.Exit(2)
	}
	data, err := os.ReadFile(os.Args[1])
	if err != nil {
		panic(err)
	}
	var input Input
	if err := json.Unmarshal(data, &input); err != nil {
		panic(err)
	}
	results := []map[string]any{}
	for _, contract := range input.Contracts {
		replayPassed, actual := evaluate(contract, false)
		mutantRejected := false
		if replayPassed {
			mutantPassed, _ := evaluate(contract, true)
			mutantRejected = !mutantPassed
		}
		status := "failed"
		if replayPassed && mutantRejected {
			status = "passed"
		}
		results = append(results, map[string]any{
			"name":            contract.Name,
			"version":         contract.Version,
			"capability":      contract.Capability,
			"source_kind":     contract.SourceKind,
			"op":              contract.Op,
			"replay_passed":   replayPassed,
			"mutant_rejected": mutantRejected,
			"status":          status,
			"actual":          actual,
		})
	}
	out, err := json.Marshal(map[string]any{"results": results})
	if err != nil {
		panic(err)
	}
	fmt.Println(string(out))
}
