package modules

import (
	"context"
	"runtime"
	"strings"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/parse"
	"github.com/puck-security/geiger/internal/recognize"
	"github.com/puck-security/geiger/internal/recon"
)

// Public GPP cpassword test vector (MS14-025): decrypts to "GPPstillStandingStrong2k18".
const gppVector = "edBSHOwhZLTjt/QS9FeIcJ83mjWA98gw9guKOhJOdcqh+ZGMeXOsQbCpZ3xUjTLfCuNH8pG5aSVYdYw/NglVmQ"

func TestGPPDecryptKnownVector(t *testing.T) {
	pw, err := decryptGPPCpassword(gppVector)
	if err != nil {
		t.Fatal(err)
	}
	if pw != "GPPstillStandingStrong2k18" {
		t.Errorf("decrypt = %q, want GPPstillStandingStrong2k18", pw)
	}
}

func TestGPPRecognizeAndRecon(t *testing.T) {
	xml := `<?xml version="1.0"?><Groups><User><Properties action="U" newName="" cpassword="` + gppVector +
		`" userName="DOMAIN\svc-backup"/></User></Groups>`
	b := parse.Parse(xml, "Groups.xml")
	ms := recognize.Recognize(b, "", module.Default)
	var m *recognize.Match
	for i := range ms {
		if ms[i].Module == "gpp_cpassword" {
			m = &ms[i]
		}
	}
	if m == nil {
		t.Fatalf("cpassword not recognized: %+v", ms)
	}
	if m.Fields["username"] != `DOMAIN\svc-backup` {
		t.Errorf("username = %q", m.Fields["username"])
	}
	fs, _ := gppCpassword{}.Recon(context.Background(), nil, module.Token{}, m.Fields)
	got := indexByKey(fs)
	if got["password"].Flag != module.FlagForceMultiplier || !strings.Contains(got["password"].Value, "GPPstillStandingStrong2k18") {
		t.Errorf("password finding wrong: %+v", got["password"])
	}
	if got["account"].Value != `DOMAIN\svc-backup` {
		t.Errorf("account = %q", got["account"].Value)
	}
}

func TestGPPEmptyCpasswordIgnored(t *testing.T) {
	// A cleared password (cpassword="") is not a secret.
	b := parse.Parse(`<Properties cpassword="" userName="x"/>`, "Groups.xml")
	for _, m := range recognize.Recognize(b, "", module.Default) {
		if m.Module == "gpp_cpassword" {
			t.Errorf("empty cpassword should not be recognized: %+v", m)
		}
	}
}

func TestGPPValidationGatedOnIntrusive(t *testing.T) {
	f := module.Fields{"cpassword": gppVector, "username": `DOMAIN\svc`}

	// not intrusive: no validation finding
	c := recon.New(nil, false)
	fs, _ := gppCpassword{}.Recon(context.Background(), c, module.Token{}, f)
	if _, ok := indexByKey(fs)["validation"]; ok {
		t.Errorf("validation must not run without --intrusive: %+v", fs)
	}

	// intrusive: validation attempted. On a non-Windows host it reports skipped;
	// on Windows it would report VALID or rejected.
	c.SetIntrusive(true)
	fs, _ = gppCpassword{}.Recon(context.Background(), c, module.Token{}, f)
	v, ok := indexByKey(fs)["validation"]
	if !ok {
		t.Fatalf("intrusive run should attempt validation: %+v", fs)
	}
	if runtime.GOOS != "windows" && !strings.Contains(v.Value, "only on a Windows host") {
		t.Errorf("non-Windows validation should say skipped, got %q", v.Value)
	}
}
