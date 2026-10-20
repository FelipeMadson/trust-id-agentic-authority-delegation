package tests

import (
	"testing"
	"time"

	"github.com/FelipeMadson/trust-id-agentic-authority-delegation/pkg/delegation"
	"github.com/FelipeMadson/trust-id-agentic-authority-delegation/pkg/identity"
)

func TestAuthorityDelegationChainAndAttenuation(t *testing.T) {
	reg := identity.NewIdentityRegistry()

	// Entities
	humanKP, _, _ := reg.GenerateIdentity("Lead Researcher", identity.TypeHumanPrincipal)
	coordKP, _, _ := reg.GenerateIdentity("Coordinator Agent", identity.TypeCoordinatorAgent)
	workerKP, _, _ := reg.GenerateIdentity("Worker Sub-Agent", identity.TypeWorkerAgent)

	// Level 0: Human -> Coordinator
	principalScope := delegation.PermissionScope{
		AllowedDataspaces: []string{"br.rnp.dataspace.genomics", "br.rnp.dataspace.climate"},
		AllowedActions:    []string{"READ", "QUERY", "ANALYZE", "EXPORT"},
		MaxComputeCredits: 1000,
		MaxQueryRows:      50000,
	}

	chain, err := delegation.NewDelegationChain(humanKP, coordKP.DID, principalScope, 8*time.Hour)
	if err != nil {
		t.Fatalf("failed to create root delegation chain: %v", err)
	}

	// Level 1: Coordinator -> Worker (Attenuated: only genomics, only READ/QUERY, 200 credits, 5000 rows, 2 hours)
	attenuatedScope := delegation.PermissionScope{
		AllowedDataspaces: []string{"br.rnp.dataspace.genomics"},
		AllowedActions:    []string{"READ", "QUERY"},
		MaxComputeCredits: 200,
		MaxQueryRows:      5000,
	}

	err = chain.SubDelegate(coordKP, workerKP.DID, attenuatedScope, 2*time.Hour)
	if err != nil {
		t.Fatalf("failed to sub-delegate: %v", err)
	}

	// Verify complete chain
	valid, err := chain.VerifyChain(reg)
	if !valid || err != nil {
		t.Fatalf("expected valid chain verification, got: %v", err)
	}

	if chain.LeafAgentDID != workerKP.DID {
		t.Fatalf("expected leaf agent to be worker %s, got %s", workerKP.DID, chain.LeafAgentDID)
	}

	eff := chain.GetEffectiveScope()
	if eff.MaxComputeCredits != 200 || len(eff.AllowedDataspaces) != 1 {
		t.Fatalf("effective scope not properly attenuated: %+v", eff)
	}

	// Test Attenuation Invariant Violation: Worker tries to exceed credits
	invalidScope := delegation.PermissionScope{
		AllowedDataspaces: []string{"br.rnp.dataspace.genomics"},
		AllowedActions:    []string{"READ"},
		MaxComputeCredits: 9999, // Exceeds parent 1000
		MaxQueryRows:      1000,
	}
	workerViolatorKP, _, _ := reg.GenerateIdentity("Rogue Worker", identity.TypeWorkerAgent)

	err = chain.SubDelegate(coordKP, workerViolatorKP.DID, invalidScope, 1*time.Hour)
	if err == nil {
		t.Fatalf("expected sub-delegation to fail due to credit attenuation violation")
	}
}
