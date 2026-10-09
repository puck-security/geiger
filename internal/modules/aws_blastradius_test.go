package modules

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

func findByKeyAll(fs []module.Finding, key string) []module.Finding {
	var out []module.Finding
	for _, f := range fs {
		if f.Key == key {
			out = append(out, f)
		}
	}
	return out
}

// Simulate now batches privesc + reach primitives in one call. Reach hits are
// grouped into a single "capabilities" force multiplier; with no privesc edge
// the "no escalation edge" line still appears.
func TestSimulateReachCapabilities(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<x><EvaluationResults>
		<member><EvalActionName>s3:GetObject</EvalActionName><EvalDecision>allowed</EvalDecision></member>
		<member><EvalActionName>kms:Decrypt</EvalActionName><EvalDecision>allowed</EvalDecision></member>
		<member><EvalActionName>iam:CreateAccessKey</EvalActionName><EvalDecision>implicitDeny</EvalDecision></member>
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

	caps := findByKeyAll(fs, "capabilities")
	if len(caps) != 1 || caps[0].Flag != module.FlagForceMultiplier {
		t.Fatalf("expected one capabilities force-multiplier, got %+v", fs)
	}
	if !strings.Contains(caps[0].Value, "s3:GetObject") || !strings.Contains(caps[0].Value, "kms:Decrypt") {
		t.Errorf("capabilities value = %q", caps[0].Value)
	}
	pe := findByKeyAll(fs, "privesc")
	if len(pe) != 1 || !strings.Contains(pe[0].Value, "no escalation edge") {
		t.Errorf("expected no-escalation-edge line, got %+v", pe)
	}
}

func TestAccountAuthDetailsPaginatesAndCounts(t *testing.T) {
	page := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		page++
		if page == 1 {
			_, _ = w.Write([]byte(`<r><UserDetailList><member><UserId>U1</UserId></member><member><UserId>U2</UserId></member></UserDetailList>` +
				`<RoleDetailList><member><RoleId>R1</RoleId></member></RoleDetailList>` +
				`<IsTruncated>true</IsTruncated><Marker>M1</Marker></r>`))
			return
		}
		_, _ = w.Write([]byte(`<r><GroupDetailList><member><GroupId>G1</GroupId></member></GroupDetailList>` +
			`<Policies><member><PolicyId>P1</PolicyId></member><member><PolicyId>P2</PolicyId></member></Policies>` +
			`<IsTruncated>false</IsTruncated></r>`))
	}))
	defer srv.Close()
	orig := awsEndpoints
	awsEndpoints.IAM = srv.URL + "/"
	defer func() { awsEndpoints = orig }()

	c := recon.New(srv.Client(), true)
	fnd, ok := awsKey{}.accountAuthDetails(context.Background(), c, module.Fields{"access_key": "AKIA", "secret_key": "s"})
	if !ok {
		t.Fatal("expected account authorization detail to be readable")
	}
	if fnd.Flag != module.FlagForceMultiplier {
		t.Errorf("flag = %v", fnd.Flag)
	}
	// 2 users + 1 role = 3 principals; 1 group; 2 managed policies.
	if !strings.HasPrefix(fnd.Value, "3 IAM principals") ||
		!strings.Contains(fnd.Value, "2 users") || !strings.Contains(fnd.Value, "1 roles") ||
		!strings.Contains(fnd.Value, "1 groups") || !strings.Contains(fnd.Value, "2 managed policies") {
		t.Errorf("value = %q", fnd.Value)
	}
	if page != 2 {
		t.Errorf("expected 2 pages fetched, got %d", page)
	}
}

func TestAccountAuthDetailsDeniedReturnsFalse(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	orig := awsEndpoints
	awsEndpoints.IAM = srv.URL + "/"
	defer func() { awsEndpoints = orig }()

	c := recon.New(srv.Client(), true)
	if _, ok := (awsKey{}).accountAuthDetails(context.Background(), c, module.Fields{"access_key": "AKIA", "secret_key": "s"}); ok {
		t.Error("denied call should report not-ok")
	}
}

func TestSelfGrantsUserProvenance(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := readAll(r)
		switch {
		case strings.Contains(body, "ListGroupsForUser"):
			_, _ = w.Write([]byte(`<r><Groups><member><GroupName>Developers</GroupName></member><member><GroupName>Admins</GroupName></member></Groups></r>`))
		case strings.Contains(body, "ListAttachedUserPolicies"):
			_, _ = w.Write([]byte(`<r><AttachedPolicies><member><PolicyName>AdministratorAccess</PolicyName></member></AttachedPolicies></r>`))
		case strings.Contains(body, "ListUserPolicies"):
			_, _ = w.Write([]byte(`<r><PolicyNames><member>inline-one</member></PolicyNames></r>`))
		default:
			w.WriteHeader(http.StatusForbidden)
		}
	}))
	defer srv.Close()
	orig := awsEndpoints
	awsEndpoints.IAM = srv.URL + "/"
	defer func() { awsEndpoints = orig }()

	c := recon.New(srv.Client(), true)
	fs := awsKey{}.selfGrants(context.Background(), c,
		module.Fields{"access_key": "AKIA", "secret_key": "s"},
		"arn:aws:iam::1234:user/ci-deploy")
	got := indexByKey(fs)
	if g, ok := got["groups"]; !ok || !strings.Contains(g.Value, "Admins") || g.Flag != module.FlagWarn {
		t.Errorf("groups finding = %+v", got["groups"])
	}
	if p, ok := got["policies"]; !ok || !strings.Contains(p.Value, "AdministratorAccess") || p.Flag != module.FlagWarn || !strings.Contains(p.Value, "1 inline") {
		t.Errorf("policies finding = %+v", got["policies"])
	}
}

func TestSelfGrantsRolePath(t *testing.T) {
	var sawRoleName string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body := readAll(r)
		if strings.Contains(body, "ListAttachedRolePolicies") {
			if v, _ := url.ParseQuery(body); v.Get("RoleName") != "" {
				sawRoleName = v.Get("RoleName")
			}
			_, _ = w.Write([]byte(`<r><AttachedPolicies><member><PolicyName>ReadOnlyAccess</PolicyName></member></AttachedPolicies></r>`))
			return
		}
		w.WriteHeader(http.StatusForbidden) // inline denied
	}))
	defer srv.Close()
	orig := awsEndpoints
	awsEndpoints.IAM = srv.URL + "/"
	defer func() { awsEndpoints = orig }()

	c := recon.New(srv.Client(), true)
	fs := awsKey{}.selfGrants(context.Background(), c,
		module.Fields{"access_key": "ASIA", "secret_key": "s"},
		"arn:aws:sts::1234:assumed-role/AdminRole/sessionX")
	if sawRoleName != "AdminRole" {
		t.Errorf("expected role name AdminRole derived from session ARN, got %q", sawRoleName)
	}
	got := indexByKey(fs)
	if p, ok := got["policies"]; !ok || !strings.Contains(p.Value, "ReadOnlyAccess") {
		t.Errorf("policies finding = %+v", got["policies"])
	}
}

func TestAccessKeyLastUsedDormant(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<r><GetAccessKeyLastUsedResult><UserName>ci</UserName><AccessKeyLastUsed><LastUsedDate>2020-01-02T00:00:00Z</LastUsedDate><ServiceName>s3</ServiceName></AccessKeyLastUsed></GetAccessKeyLastUsedResult></r>`))
	}))
	defer srv.Close()
	orig := awsEndpoints
	awsEndpoints.IAM = srv.URL + "/"
	defer func() { awsEndpoints = orig }()

	c := recon.New(srv.Client(), true)
	fnd, ok := awsKey{}.accessKeyLastUsed(context.Background(), c, module.Fields{"access_key": "AKIAEXAMPLE", "secret_key": "s"})
	if !ok || fnd.Flag != module.FlagWarn || !strings.Contains(fnd.Value, "dormant") || !strings.Contains(fnd.Value, "s3") {
		t.Errorf("dormant key finding = %+v ok=%v", fnd, ok)
	}
}

func TestAccessKeyLastUsedNeverUsed(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<r><GetAccessKeyLastUsedResult><UserName>ci</UserName><AccessKeyLastUsed><ServiceName>N/A</ServiceName></AccessKeyLastUsed></GetAccessKeyLastUsedResult></r>`))
	}))
	defer srv.Close()
	orig := awsEndpoints
	awsEndpoints.IAM = srv.URL + "/"
	defer func() { awsEndpoints = orig }()

	c := recon.New(srv.Client(), true)
	fnd, ok := awsKey{}.accessKeyLastUsed(context.Background(), c, module.Fields{"access_key": "AKIAEXAMPLE", "secret_key": "s"})
	if !ok || !strings.Contains(fnd.Value, "never used") {
		t.Errorf("never-used finding = %+v", fnd)
	}
}

func TestAccessKeyLastUsedSkipsTempKey(t *testing.T) {
	c := recon.New(http.DefaultClient, false)
	if _, ok := (awsKey{}).accessKeyLastUsed(context.Background(), c, module.Fields{"access_key": "ASIATEMP"}); ok {
		t.Error("temporary ASIA key should be skipped")
	}
}

func TestRoleGraphGatedOnAWSIntrusive(t *testing.T) {
	c := recon.New(http.DefaultClient, true) // live but not aws-intrusive
	c.SetIntrusive(true)                     // generic intrusive must NOT enable it
	if fs := (awsKey{}).roleGraph(context.Background(), c, module.Fields{"access_key": "AKIA"}, "arn:aws:iam::111111111111:user/ci"); fs != nil {
		t.Errorf("roleGraph must not run without --aws-intrusive, got %+v", fs)
	}
}

func TestRoleGraphClassifiesTrust(t *testing.T) {
	enc := func(doc string) string { return url.QueryEscape(doc) }
	world := `{"Version":"2012-10-17","Statement":[{"Effect":"Allow","Principal":{"AWS":"*"},"Action":"sts:AssumeRole"}]}`
	inAcct := `{"Statement":{"Effect":"Allow","Principal":{"AWS":"arn:aws:iam::111111111111:root"},"Action":"sts:AssumeRole"}}`
	external := `{"Statement":[{"Effect":"Allow","Principal":{"AWS":["arn:aws:iam::999999999999:root","arn:aws:iam::111111111111:role/ci"]},"Action":"sts:AssumeRole"}]}`

	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte(`<r><Roles>` +
			`<member><RoleName>W</RoleName><AssumeRolePolicyDocument>` + enc(world) + `</AssumeRolePolicyDocument></member>` +
			`<member><RoleName>I</RoleName><AssumeRolePolicyDocument>` + enc(inAcct) + `</AssumeRolePolicyDocument></member>` +
			`<member><RoleName>E</RoleName><AssumeRolePolicyDocument>` + enc(external) + `</AssumeRolePolicyDocument></member>` +
			`</Roles><IsTruncated>false</IsTruncated></r>`))
	}))
	defer srv.Close()
	orig := awsEndpoints
	awsEndpoints.IAM = srv.URL + "/"
	defer func() { awsEndpoints = orig }()

	c := recon.New(srv.Client(), true)
	c.SetAWSIntrusive(true)
	fs := awsKey{}.roleGraph(context.Background(), c, module.Fields{"access_key": "AKIA", "secret_key": "s"},
		"arn:aws:iam::111111111111:user/ci")

	assumable := findByKeyAll(fs, "assumable roles")
	var world1, inAcct1 bool
	for _, f := range assumable {
		if strings.Contains(f.Value, "world-assumable") && f.Flag == module.FlagForceMultiplier {
			world1 = true
		}
		if strings.Contains(f.Value, "in-account") && f.Flag == module.FlagWarn {
			inAcct1 = true
		}
	}
	if !world1 || !inAcct1 {
		t.Errorf("assumable findings wrong: %+v", assumable)
	}
	cross := findByKeyAll(fs, "cross-account trust")
	if len(cross) != 1 || !strings.Contains(cross[0].Value, "999999999999") || strings.Contains(cross[0].Value, "111111111111") {
		t.Errorf("cross-account finding wrong: %+v", cross)
	}
}

func TestTrustPrincipalsParsing(t *testing.T) {
	// array principal + single-object statement + string "*"
	cases := []struct {
		doc  string
		want []string
	}{
		{`{"Statement":[{"Effect":"Allow","Principal":{"AWS":"arn:a"}}]}`, []string{"arn:a"}},
		{`{"Statement":{"Effect":"Allow","Principal":{"AWS":["x","y"]}}}`, []string{"x", "y"}},
		{`{"Statement":[{"Effect":"Allow","Principal":"*"}]}`, []string{"*"}},
		{`{"Statement":[{"Effect":"Deny","Principal":{"AWS":"z"}}]}`, nil},
		{`{"Statement":[{"Effect":"Allow","Principal":{"Service":"ec2.amazonaws.com"}}]}`, nil},
	}
	for i, tc := range cases {
		got := trustPrincipals(tc.doc)
		if strings.Join(got, ",") != strings.Join(tc.want, ",") {
			t.Errorf("case %d: got %v want %v", i, got, tc.want)
		}
	}
}
