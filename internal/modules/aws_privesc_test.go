package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

func TestRoleARNFor(t *testing.T) {
	cases := map[string]string{
		"arn:aws:iam::1234:user/ci-deploy":                  "arn:aws:iam::1234:user/ci-deploy",
		"arn:aws:sts::1234:assumed-role/AdminRole/sessionX": "arn:aws:iam::1234:role/AdminRole",
		"arn:aws:iam::1234:role/SomeRole":                   "arn:aws:iam::1234:role/SomeRole",
		"arn:aws:sts::1234:federated-user/x":                "",
	}
	for in, want := range cases {
		if got := roleARNFor(in); got != want {
			t.Errorf("roleARNFor(%q)=%q want %q", in, got, want)
		}
	}
}

func TestAllowedActions(t *testing.T) {
	xml := `<SimulatePrincipalPolicyResponse><SimulatePrincipalPolicyResult><EvaluationResults>
	<member><EvalActionName>iam:CreateAccessKey</EvalActionName><EvalDecision>allowed</EvalDecision></member>
	<member><EvalActionName>sts:AssumeRole</EvalActionName><EvalDecision>implicitDeny</EvalDecision></member>
	</EvaluationResults></SimulatePrincipalPolicyResult></SimulatePrincipalPolicyResponse>`
	got := allowedActions([]byte(xml))
	if !got["iam:CreateAccessKey"] || got["sts:AssumeRole"] {
		t.Errorf("allowedActions wrong: %+v", got)
	}
}

func TestPrivescReportsAllowedEdges(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<x><EvaluationResults>
		<member><EvalActionName>iam:CreateAccessKey</EvalActionName><EvalDecision>allowed</EvalDecision></member>
		<member><EvalActionName>iam:AttachUserPolicy</EvalActionName><EvalDecision>allowed</EvalDecision></member>
		</EvaluationResults></x>`))
	}))
	defer srv.Close()
	orig := awsEndpoints
	awsEndpoints.IAM = srv.URL + "/"
	defer func() { awsEndpoints = orig }()

	c := recon.New(srv.Client(), true)
	fs := awsKey{}.privesc(context.Background(), c,
		module.Fields{"access_key": "AKIA", "secret_key": "s"},
		"arn:aws:iam::1234:user/ci-deploy")
	hits := 0
	for _, f := range fs {
		if f.Key == "privesc" && f.Flag == module.FlagForceMultiplier {
			hits++
		}
	}
	if hits != 2 {
		t.Errorf("expected 2 privesc force-multipliers, got %d: %+v", hits, fs)
	}
	if !strings.Contains(fs[0].Value, "CreateAccessKey") {
		t.Errorf("unexpected first finding: %q", fs[0].Value)
	}
}
