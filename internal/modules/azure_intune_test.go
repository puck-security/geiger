package modules

import (
	"context"
	"testing"

	"github.com/puck-security/geiger/internal/module"
	"github.com/puck-security/geiger/internal/recon"
)

func TestAzureMSALIntuneFlag(t *testing.T) {
	mod, ok := module.Default.ByName("azure_msal")
	if !ok {
		t.Fatal("azure_msal not registered")
	}
	c := recon.New(nil, false) // offline: the scope check is purely local

	// A token scoped to Intune managed devices can remotely wipe — force multiplier.
	fs, _ := mod.Recon(context.Background(), c, module.Token{}, module.Fields{
		"scopes":   "https://graph.microsoft.com/DeviceManagementManagedDevices.PrivilegedOperations.All",
		"username": "admin@acme.com",
	})
	if indexByKey(fs)["intune"].Flag != module.FlagForceMultiplier {
		t.Errorf("Intune device-management scope should raise a force multiplier: %+v", fs)
	}

	// An ordinary Graph token must NOT flag Intune.
	fs2, _ := mod.Recon(context.Background(), c, module.Token{}, module.Fields{
		"scopes":   "https://graph.microsoft.com/.default offline_access",
		"username": "u@acme.com",
	})
	if _, flagged := indexByKey(fs2)["intune"]; flagged {
		t.Errorf("a non-Intune token must not be flagged for device wipe: %+v", fs2)
	}
}
