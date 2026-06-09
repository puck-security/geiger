package modules

import "testing"

func TestFirstVarStageDecorations(t *testing.T) {
	if v := firstVar(map[string]string{"COHERE_API_KEY": "exact"}, "COHERE_API_KEY"); v != "exact" {
		t.Errorf("exact match broken: %q", v)
	}
	if v := firstVar(map[string]string{"STAGING_COHERE_API_KEY": "staged"}, "COHERE_API_KEY"); v != "staged" {
		t.Errorf("stage prefix not matched: %q", v)
	}
	if v := firstVar(map[string]string{"GEMINI_API_KEY_PROD": "p"}, "GEMINI_API_KEY"); v != "p" {
		t.Errorf("stage suffix not matched: %q", v)
	}
	// exact must win over a decorated variant
	if v := firstVar(map[string]string{"COHERE_API_KEY": "exact", "PROD_COHERE_API_KEY": "dec"}, "COHERE_API_KEY"); v != "exact" {
		t.Errorf("exact should win over decorated: %q", v)
	}
	// an unrelated var must NOT match (no loose substring matching)
	if v := firstVar(map[string]string{"SOME_OTHER_KEY": "x"}, "COHERE_API_KEY"); v != "" {
		t.Errorf("unrelated var matched: %q", v)
	}
	// a mid-string variant (ANON) must NOT be matched as the canonical key
	if v := firstVar(map[string]string{"SUPABASE_ANON_KEY": "anon"}, "SUPABASE_KEY"); v != "" {
		t.Errorf("distinct variant wrongly matched: %q", v)
	}
}
