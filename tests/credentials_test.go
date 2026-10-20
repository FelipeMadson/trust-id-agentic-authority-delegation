package tests

import (
	"testing"
	"time"

	"github.com/FelipeMadson/trust-id-agentic-authority-delegation/pkg/credentials"
	"github.com/FelipeMadson/trust-id-agentic-authority-delegation/pkg/identity"
)

func TestVerifiableCredentialLifecycle(t *testing.T) {
	reg := identity.NewIdentityRegistry()
	revReg := credentials.NewRevocationRegistry("https://trust-id.rnp.br/status")

	issuerKP, _, err := reg.GenerateIdentity("RNP-DPDI-Authority", identity.TypeHumanPrincipal)
	if err != nil {
		t.Fatal(err)
	}

	agentKP, _, err := reg.GenerateIdentity("ScientificPipelineAgent", identity.TypeCoordinatorAgent)
	if err != nil {
		t.Fatal(err)
	}

	claims := map[string]interface{}{
		"id":                 agentKP.DID,
		"authorizedResearch": "GenomicEpidemiology",
		"trustLevel":         "Tier-1",
		"maxMemoryGB":        64,
	}

	credID := "urn:uuid:rnp-vc-2026-test-01"
	vc, err := credentials.IssueCredential(issuerKP, credID, []string{"ScientificAuthorizationCredential"}, claims, 2*time.Hour, revReg)
	if err != nil {
		t.Fatalf("issue credential failed: %v", err)
	}

	// 1. Valid verification
	valid, err := credentials.VerifyCredential(vc, reg, revReg)
	if !valid || err != nil {
		t.Fatalf("expected valid VC, got err: %v", err)
	}

	// 2. Presentation creation and verification
	vp, err := credentials.CreatePresentation(agentKP, "urn:uuid:vp-2026-agent", []*credentials.VerifiableCredential{vc})
	if err != nil {
		t.Fatalf("create presentation failed: %v", err)
	}

	vpValid, err := credentials.VerifyPresentation(vp, reg, revReg)
	if !vpValid || err != nil {
		t.Fatalf("expected valid VP, got err: %v", err)
	}

	// 3. Revocation verification
	revReg.Revoke(credID)
	revValid, _ := credentials.VerifyCredential(vc, reg, revReg)
	if revValid {
		t.Fatalf("expected revoked credential to fail validation")
	}
}
