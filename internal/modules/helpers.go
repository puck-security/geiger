package modules

import (
	"encoding/json"
	"fmt"
	"regexp"
)

// jsonField decodes body and returns the top-level string field key, or "".
func jsonField(body []byte, key string) string {
	var m map[string]any
	if json.Unmarshal(body, &m) != nil {
		return ""
	}
	if v, ok := m[key].(string); ok {
		return v
	}
	if v, ok := m[key].(float64); ok {
		return fmt.Sprintf("%v", v)
	}
	return ""
}

// jsonDecode decodes body into a generic map.
func jsonDecode(body []byte) map[string]any {
	var m map[string]any
	_ = json.Unmarshal(body, &m)
	return m
}

// jsonDecodeArray decodes a top-level JSON array body (e.g. 1Password Connect
// /v1/vaults), returning the slice and whether it parsed.
func jsonDecodeArray(body []byte) ([]any, bool) {
	var a []any
	if json.Unmarshal(body, &a) != nil {
		return nil, false
	}
	return a, true
}

func errStatus(code int) error {
	return fmt.Errorf("status %d", code)
}

var xmlTagCache = map[string]*regexp.Regexp{}

func xmlRe(tag string) *regexp.Regexp {
	if re, ok := xmlTagCache[tag]; ok {
		return re
	}
	re := regexp.MustCompile(`<` + regexp.QuoteMeta(tag) + `>([^<]*)</` + regexp.QuoteMeta(tag) + `>`)
	xmlTagCache[tag] = re
	return re
}

// xmlField returns the first <tag>value</tag> text, or "".
func xmlField(body []byte, tag string) string {
	m := xmlRe(tag).FindSubmatch(body)
	if m == nil {
		return ""
	}
	return string(m[1])
}

// xmlFields returns all <tag>value</tag> texts.
func xmlFields(body []byte, tag string) []string {
	var out []string
	for _, m := range xmlRe(tag).FindAllSubmatch(body, -1) {
		out = append(out, string(m[1]))
	}
	return out
}

// jsonQuote returns a JSON-quoted string literal (for building small request bodies).
func jsonQuote(s string) string {
	b, _ := json.Marshal(s)
	return string(b)
}
