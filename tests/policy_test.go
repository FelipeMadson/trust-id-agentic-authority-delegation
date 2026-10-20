package tests

import (
	"testing"
	"time"

	"github.com/FelipeMadson/trust-id-agentic-authority-delegation/pkg/delegation"
	"github.com/FelipeMadson/trust-id-agentic-authority-delegation/pkg/identity"
	"github.com/FelipeMadson/trust-id-agentic-authority-delegation/pkg/policy"
)

func TestPolicyEvaluationWithDelegation(t *testing.T) {
	reg := identity.NewIdentityRegistry()
	pe := policy.NewPolicyEngine()

	humanKP, _, _ := reg.GenerateIdentity("Investigator", identity.TypeHumanPrincipal)
	agentKP, _, _ := reg.GenerateIdentity("GenomicBot", identity.TypeCoordinatorAgent)

	scope := delegation.PermissionScope{
		AllowedDataspaces: []string{"br.rnp.dataspace.genomics"},
		AllowedActions:    []string{"READ", "QUERY", "ANALYZE"},
		MaxComputeCredits: 500,
		MaxQueryRows:      25000,
	}

	chain, err := delegation.NewDelegationChain(humanKP, agentKP.DID, scope, 4*time.Hour)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Authorized Request
	req := &policy.AccessRequest{
		AgentDID:        agentKP.DID,
		AgentType:       identity.TypeCoordinatorAgent,
		Dataspace:       "br.rnp.dataspace.genomics",
		ResourceID:      "genomic-variant-db-2026",
		Action:          "QUERY",
		RequestedRows:   10000,
		RequestedCredit: 100,
		DelegationChain: chain,
	}

	dec, err := pe.Evaluate(req, reg)
	if err != nil {
		t.Fatalf("policy evaluation returned error: %v", err)
	}

	if !dec.Allow {
		t.Fatalf("expected request to be allowed, got denied with reasons: %v", dec.Reasons)
	}

	if len(dec.Obligations) == 0 {
		t.Fatalf("expected obligations to be attached, got 0")
	}

	// 2. Denied Request (Action unauthorized in policy)
	forbiddenReq := &policy.AccessRequest{
		AgentDID:        agentKP.DID,
		AgentType:       identity.TypeCoordinatorAgent,
		Dataspace:       "br.rnp.dataspace.genomics",
		ResourceID:      "genomic-variant-db-2026",
		Action:          "DELETE_DATASET", // Not in rule
		RequestedRows:   100,
		RequestedCredit: 10,
		DelegationChain: chain,
	}

	decForbid, _ := pe.Evaluate(forbiddenReq, reg)
	if decForbid.Allow {
		t.Fatalf("expected forbidden action to be rejected")
	}
}
