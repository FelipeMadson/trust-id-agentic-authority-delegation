package tests

import (
	"strings"
	"testing"

	"github.com/FelipeMadson/trust-id-agentic-authority-delegation/pkg/identity"
)

func TestIdentityGenerationAndDIDKey(t *testing.T) {
	reg := identity.NewIdentityRegistry()

	kp, doc, err := reg.GenerateIdentity("GenomicCoordinator-01", identity.TypeCoordinatorAgent)
	if err != nil {
		t.Fatalf("expected successful identity generation, got: %v", err)
	}

	if !strings.HasPrefix(kp.DID, "did:key:z") {
		t.Fatalf("expected did:key:z prefix, got: %s", kp.DID)
	}

	if doc.ID != kp.DID {
		t.Fatalf("expected doc ID %s, got %s", kp.DID, doc.ID)
	}

	if len(doc.VerificationMethod) != 1 {
		t.Fatalf("expected 1 verificationMethod, got %d", len(doc.VerificationMethod))
	}

	if doc.VerificationMethod[0].Type != "Ed25519VerificationKey2020" {
		t.Fatalf("expected Ed25519VerificationKey2020, got %s", doc.VerificationMethod[0].Type)
	}

	// Dynamic Resolution
	resolved, err := identity.ResolveDIDKey(kp.DID)
	if err != nil {
		t.Fatalf("dynamic resolve failed: %v", err)
	}

	if resolved.ID != kp.DID {
		t.Fatalf("resolved DID mismatch: expected %s, got %s", kp.DID, resolved.ID)
	}
}

func TestSignatureVerification(t *testing.T) {
	reg := identity.NewIdentityRegistry()
	kp, _, err := reg.GenerateIdentity("Worker-Agent-Alpha", identity.TypeWorkerAgent)
	if err != nil {
		t.Fatal(err)
	}

	message := []byte("ACTION:QUERY_GENOMICS_DATASET_SNP_2026")
	sig := kp.SignMessage(message)

	pub, err := identity.ExtractPublicKey(kp.DID)
	if err != nil {
		t.Fatalf("failed to extract public key: %v", err)
	}

	if !identity.VerifySignature(pub, message, sig) {
		t.Fatalf("valid signature rejected")
	}

	// Tampered message check
	tampered := []byte("ACTION:DELETE_GENOMICS_DATASET_SNP_2026")
	if identity.VerifySignature(pub, tampered, sig) {
		t.Fatalf("tampered message accepted unexpectedly")
	}
}
