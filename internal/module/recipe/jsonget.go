package recipe

import (
	"strconv"
	"strings"
)

// get walks a decoded JSON value by a dotted path. Segments are object keys or
// array indices: "account.email", "data.0.id", "results.2.name". It returns the
// value and whether the path resolved.
func get(v any, path string) (any, bool) {
	if path == "" {
		return v, true
	}
	cur := v
	for _, seg := range strings.Split(path, ".") {
		switch node := cur.(type) {
		case map[string]any:
			next, ok := node[seg]
			if !ok {
				return nil, false
			}
			cur = next
		case []any:
			i, err := strconv.Atoi(seg)
			if err != nil || i < 0 || i >= len(node) {
				return nil, false
			}
			cur = node[i]
		default:
			return nil, false
		}
	}
	return cur, true
}

// getString resolves a path and renders the leaf as a string.
func getString(v any, path string) (string, bool) {
	leaf, ok := get(v, path)
	if !ok || leaf == nil {
		return "", false
	}
	return toString(leaf), true
}

func toString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case bool:
		if t {
			return "true"
		}
		return "false"
	case float64:
		// render integers without trailing .0
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'g', -1, 64)
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			parts = append(parts, toString(e))
		}
		return strings.Join(parts, ", ")
	default:
		return ""
	}
}

// arrayLen returns the length of a JSON array at path (0 if not an array).
func arrayLen(v any, path string) (int, bool) {
	leaf, ok := get(v, path)
	if !ok {
		return 0, false
	}
	if arr, ok := leaf.([]any); ok {
		return len(arr), true
	}
	return 0, false
}
