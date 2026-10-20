package tests

import (
	"testing"

	"github.com/FelipeMadson/trust-id-agentic-authority-delegation/pkg/audit"
)

func TestMerkleAuditTreeAndInclusionProof(t *testing.T) {
	tree := audit.NewMerkleAuditTree()

	// Append 5 records
	rec1, root1, err := tree.AppendRecord("rec-001", "did:key:zAgent1", "did:key:zPrincipal", "br.rnp.genomics", "QUERY", "db-1", true, "sig1")
	if err != nil {
		t.Fatal(err)
	}

	if root1 == "" || tree.Size() != 1 {
		t.Fatalf("expected tree size 1, got %d", tree.Size())
	}

	tree.AppendRecord("rec-002", "did:key:zAgent2", "did:key:zPrincipal", "br.rnp.climate", "READ", "sensor-7", true, "sig2")
	tree.AppendRecord("rec-003", "did:key:zAgent3", "did:key:zPrincipal", "br.rnp.hpc", "EXECUTE_PIPELINE", "pipe-9", false, "sig3")
	tree.AppendRecord("rec-004", "did:key:zAgent1", "did:key:zPrincipal", "br.rnp.genomics", "ANALYZE", "db-2", true, "sig4")
	tree.AppendRecord("rec-005", "did:key:zAgent2", "did:key:zPrincipal", "br.rnp.climate", "QUERY", "sensor-8", true, "sig5")

	if tree.Size() != 5 {
		t.Fatalf("expected 5 records in tree, got %d", tree.Size())
	}

	currentRoot := tree.GetCurrentRoot()

	// 1. Generate inclusion proof for rec-001
	proof1, err := tree.GenerateInclusionProof("rec-001")
	if err != nil {
		t.Fatalf("failed to generate proof: %v", err)
	}

	if proof1.RootHash != currentRoot {
		t.Fatalf("proof root mismatch: %s != %s", proof1.RootHash, currentRoot)
	}

	valid, err := audit.VerifyInclusionProof(proof1)
	if !valid || err != nil {
		t.Fatalf("valid inclusion proof failed verification: %v", err)
	}

	// 2. Generate inclusion proof for rec-004
	proof4, err := tree.GenerateInclusionProof("rec-004")
	if err != nil {
		t.Fatalf("failed to generate proof 4: %v", err)
	}

	valid4, err := audit.VerifyInclusionProof(proof4)
	if !valid4 || err != nil {
		t.Fatalf("valid inclusion proof 4 failed: %v", err)
	}

	// 3. Negative test: Corrupt leaf hash
	corruptProof := *proof1
	corruptProof.LeafHash = "0000000000000000000000000000000000000000000000000000000000000000"
	corruptValid, _ := audit.VerifyInclusionProof(&corruptProof)
	if corruptValid {
		t.Fatalf("tampered proof verified unexpectedly")
	}

	_ = rec1
}
