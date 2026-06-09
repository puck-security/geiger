package parse

import "testing"

func TestParseDotenv(t *testing.T) {
	b := Parse("export GITHUB_TOKEN=ghp_abc\n# comment\nAWS_REGION=us-east-1\n", ".env")
	if b.Vars["GITHUB_TOKEN"] != "ghp_abc" {
		t.Errorf("GITHUB_TOKEN = %q", b.Vars["GITHUB_TOKEN"])
	}
	if b.Vars["AWS_REGION"] != "us-east-1" {
		t.Errorf("AWS_REGION = %q", b.Vars["AWS_REGION"])
	}
}

func TestParseINIAwsCredentials(t *testing.T) {
	raw := "[default]\naws_access_key_id = AKIAEXAMPLE\naws_secret_access_key = secret123\n\n[profile prod]\naws_access_key_id = AKIAPROD\n"
	b := Parse(raw, "credentials")
	if len(b.INI) != 2 {
		t.Fatalf("sections = %d", len(b.INI))
	}
	if b.INI[0].Name != "default" || b.INI[0].Keys["aws_access_key_id"] != "AKIAEXAMPLE" {
		t.Errorf("default section wrong: %+v", b.INI[0])
	}
	if b.INI[1].Name != "prod" {
		t.Errorf("profile prefix not stripped: %q", b.INI[1].Name)
	}
	if b.Vars["prod.aws_access_key_id"] != "AKIAPROD" {
		t.Errorf("qualified var missing")
	}
}

func TestParseJSONServiceAccount(t *testing.T) {
	raw := `{"type":"service_account","project_id":"my-proj","client_email":"sa@my-proj.iam.gserviceaccount.com","private_key":"-----BEGIN PRIVATE KEY-----\nx\n-----END PRIVATE KEY-----\n"}`
	b := Parse(raw, "key.json")
	if b.JSON["type"] != "service_account" {
		t.Errorf("type = %v", b.JSON["type"])
	}
	if b.Vars["project_id"] != "my-proj" {
		t.Errorf("flattened project_id missing: %v", b.Vars)
	}
}

func TestFromEnv(t *testing.T) {
	b := FromEnv([]string{"SLACK_TOKEN=xoxb-1", "PATH=/usr/bin"})
	if b.Vars["SLACK_TOKEN"] != "xoxb-1" {
		t.Errorf("SLACK_TOKEN = %q", b.Vars["SLACK_TOKEN"])
	}
}

func TestLineTracking(t *testing.T) {
	b := Parse("A=1\nGITHUB_TOKEN=ghp_x\n# c\nDB=2\n", ".env")
	if b.Lines["GITHUB_TOKEN"] != 2 {
		t.Errorf("GITHUB_TOKEN line = %d, want 2", b.Lines["GITHUB_TOKEN"])
	}
	if b.Lines["DB"] != 4 {
		t.Errorf("DB line = %d, want 4", b.Lines["DB"])
	}
	ini := Parse("[default]\nkey = v\n\n[prod]\nkey = w\n", "creds")
	if ini.Lines["prod.key"] != 5 {
		t.Errorf("prod.key line = %d, want 5", ini.Lines["prod.key"])
	}
}
