// Package credentials implements W3C Verifiable Credentials Data Model v2.0
// and Verifiable Presentations with Ed25519Signature2020 cryptographic proofs,
// canonical JSON hashing, and StatusList2021 revocation verification for RNP TRUST-ID.
package credentials

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"sort"
	"sync"
	"time"

	"github.com/FelipeMadson/trust-id-agentic-authority-delegation/pkg/identity"
)

// Proof models the cryptographic proof attachment conforming to W3C Linked Data Proofs.
type Proof struct {
	Type               string `json:"type"`
	Created            string `json:"created"`
	VerificationMethod string `json:"verificationMethod"`
	ProofPurpose       string `json:"proofPurpose"`
	ProofValue         string `json:"proofValue"`
}

// CredentialStatus points to the revocation list status entry.
type CredentialStatus struct {
	ID                   string `json:"id"`
	Type                 string `json:"type"`
	StatusPurpose        string `json:"statusPurpose"`
	StatusListIndex      string `json:"statusListIndex"`
	StatusListCredential string `json:"statusListCredential"`
}

// VerifiableCredential conforms to W3C Verifiable Credentials 2.0 recommendation.
type VerifiableCredential struct {
	Context           []string               `json:"@context"`
	ID                string                 `json:"id"`
	Type              []string               `json:"type"`
	Issuer            string                 `json:"issuer"`
	ValidFrom         string                 `json:"validFrom"`
	ValidUntil        string                 `json:"validUntil"`
	CredentialSubject map[string]interface{} `json:"credentialSubject"`
	CredentialStatus  *CredentialStatus      `json:"credentialStatus,omitempty"`
	Proof             *Proof                 `json:"proof,omitempty"`
}

// VerifiablePresentation encapsulates one or more VCs presented by an Agent Holder.
type VerifiablePresentation struct {
	Context              []string                `json:"@context"`
	ID                   string                  `json:"id"`
	Type                 []string                `json:"type"`
	VerifiableCredential []*VerifiableCredential `json:"verifiableCredential"`
	Holder               string                  `json:"holder"`
	Proof                *Proof                  `json:"proof,omitempty"`
}

// RevocationRegistry maintains the status bitstring for issued credentials.
type RevocationRegistry struct {
	mu            sync.RWMutex
	revokedList   map[string]bool
	statusListURL string
}

// NewRevocationRegistry creates an instance of revocation tracker.
func NewRevocationRegistry(statusListURL string) *RevocationRegistry {
	return &RevocationRegistry{
		revokedList:   make(map[string]bool),
		statusListURL: statusListURL,
	}
}

// Revoke marks a credential ID as revoked.
func (r *RevocationRegistry) Revoke(credentialID string) {
	r.mu.Lock()
	defer r.mu.Unlock()
	r.revokedList[credentialID] = true
}

// IsRevoked checks if a credential ID is revoked.
func (r *RevocationRegistry) IsRevoked(credentialID string) bool {
	r.mu.RLock()
	defer r.mu.RUnlock()
	return r.revokedList[credentialID]
}

// IssueCredential signs and creates a new W3C Verifiable Credential.
func IssueCredential(
	issuerKP *identity.KeyPair,
	credID string,
	credType []string,
	subject map[string]interface{},
	ttl time.Duration,
	statusReg *RevocationRegistry,
) (*VerifiableCredential, error) {
	now := time.Now().UTC()
	until := now.Add(ttl)

	types := []string{"VerifiableCredential"}
	for _, t := range credType {
		if t != "VerifiableCredential" {
			types = append(types, t)
		}
	}

	vc := &VerifiableCredential{
		Context: []string{
			"https://www.w3.org/ns/credentials/v2",
			"https://w3id.org/security/suites/ed25519-2020/v1",
			"https://schema.rnp.br/trust-id/v1",
		},
		ID:                credID,
		Type:              types,
		Issuer:            issuerKP.DID,
		ValidFrom:         now.Format(time.RFC3339),
		ValidUntil:        until.Format(time.RFC3339),
		CredentialSubject: subject,
	}

	if statusReg != nil {
		vc.CredentialStatus = &CredentialStatus{
			ID:                   fmt.Sprintf("%s#%s", statusReg.statusListURL, credID),
			Type:                 "StatusList2021Entry",
			StatusPurpose:        "revocation",
			StatusListIndex:      credID,
			StatusListCredential: statusReg.statusListURL,
		}
	}

	// Calculate deterministic canonical hash without the Proof field
	canonBytes, err := canonicalizeCredential(vc)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize credential: %w", err)
	}

	sig := ed25519.Sign(issuerKP.PrivateKey, canonBytes)
	sigB64 := base64.RawURLEncoding.EncodeToString(sig)

	vc.Proof = &Proof{
		Type:               "Ed25519Signature2020",
		Created:            now.Format(time.RFC3339),
		VerificationMethod: fmt.Sprintf("%s#%s", issuerKP.DID, issuerKP.DID[stringsIndex(issuerKP.DID, "z"):]),
		ProofPurpose:       "assertionMethod",
		ProofValue:         sigB64,
	}

	return vc, nil
}

// VerifyCredential verifies cryptographic integrity, issuer validity, validity window, and revocation status.
func VerifyCredential(vc *VerifiableCredential, reg *identity.IdentityRegistry, statusReg *RevocationRegistry) (bool, error) {
	if vc == nil || vc.Proof == nil {
		return false, errors.New("credential or proof missing")
	}

	// 1. Time validity check
	now := time.Now().UTC()
	validFrom, err := time.Parse(time.RFC3339, vc.ValidFrom)
	if err != nil {
		return false, fmt.Errorf("invalid validFrom timestamp: %w", err)
	}
	if now.Before(validFrom) {
		return false, errors.New("credential is not yet active")
	}

	validUntil, err := time.Parse(time.RFC3339, vc.ValidUntil)
	if err != nil {
		return false, fmt.Errorf("invalid validUntil timestamp: %w", err)
	}
	if now.After(validUntil) {
		return false, errors.New("credential has expired")
	}

	// 2. Revocation check
	if statusReg != nil && statusReg.IsRevoked(vc.ID) {
		return false, errors.New("credential has been explicitly revoked")
	}

	// 3. Extract Issuer Public Key from DID Document
	issuerDoc, err := reg.Resolve(vc.Issuer)
	if err != nil {
		return false, fmt.Errorf("failed to resolve issuer DID: %w", err)
	}
	if issuerDoc.Deactivated {
		return false, errors.New("issuer identity is deactivated")
	}

	pubKey, err := identity.ExtractPublicKey(vc.Issuer)
	if err != nil {
		return false, fmt.Errorf("failed to extract public key from issuer: %w", err)
	}

	// 4. Verify cryptographic signature
	sig, err := base64.RawURLEncoding.DecodeString(vc.Proof.ProofValue)
	if err != nil {
		return false, fmt.Errorf("malformed signature base64: %w", err)
	}

	canonBytes, err := canonicalizeCredential(vc)
	if err != nil {
		return false, fmt.Errorf("canonicalization failed: %w", err)
	}

	if !ed25519.Verify(pubKey, canonBytes, sig) {
		return false, errors.New("cryptographic signature mismatch: credential is forged or tampered")
	}

	return true, nil
}

// CreatePresentation packages credentials into a signed Verifiable Presentation.
func CreatePresentation(holderKP *identity.KeyPair, presID string, vcs []*VerifiableCredential) (*VerifiablePresentation, error) {
	now := time.Now().UTC()
	vp := &VerifiablePresentation{
		Context: []string{
			"https://www.w3.org/ns/credentials/v2",
			"https://w3id.org/security/suites/ed25519-2020/v1",
		},
		ID:                   presID,
		Type:                 []string{"VerifiablePresentation"},
		VerifiableCredential: vcs,
		Holder:               holderKP.DID,
	}

	canonBytes, err := canonicalizePresentation(vp)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize presentation: %w", err)
	}

	sig := ed25519.Sign(holderKP.PrivateKey, canonBytes)
	vp.Proof = &Proof{
		Type:               "Ed25519Signature2020",
		Created:            now.Format(time.RFC3339),
		VerificationMethod: fmt.Sprintf("%s#%s", holderKP.DID, holderKP.DID[stringsIndex(holderKP.DID, "z"):]),
		ProofPurpose:       "authentication",
		ProofValue:         base64.RawURLEncoding.EncodeToString(sig),
	}

	return vp, nil
}

// VerifyPresentation validates the VP holder signature and all embedded VCs.
func VerifyPresentation(vp *VerifiablePresentation, reg *identity.IdentityRegistry, statusReg *RevocationRegistry) (bool, error) {
	if vp == nil || vp.Proof == nil {
		return false, errors.New("presentation or proof missing")
	}

	holderPub, err := identity.ExtractPublicKey(vp.Holder)
	if err != nil {
		return false, fmt.Errorf("failed to extract holder key: %w", err)
	}

	sig, err := base64.RawURLEncoding.DecodeString(vp.Proof.ProofValue)
	if err != nil {
		return false, errors.New("malformed presentation signature")
	}

	canonBytes, err := canonicalizePresentation(vp)
	if err != nil {
		return false, err
	}

	if !ed25519.Verify(holderPub, canonBytes, sig) {
		return false, errors.New("invalid holder presentation signature")
	}

	// Verify all embedded credentials
	for i, vc := range vp.VerifiableCredential {
		valid, err := VerifyCredential(vc, reg, statusReg)
		if !valid || err != nil {
			return false, fmt.Errorf("embedded credential[%d] validation failed: %w", i, err)
		}
	}

	return true, nil
}

// canonicalizeCredential creates a deterministic byte representation of a VC (omitting proof).
func canonicalizeCredential(vc *VerifiableCredential) ([]byte, error) {
	m := map[string]interface{}{
		"@context":          vc.Context,
		"id":                vc.ID,
		"type":              vc.Type,
		"issuer":            vc.Issuer,
		"validFrom":         vc.ValidFrom,
		"validUntil":        vc.ValidUntil,
		"credentialSubject": vc.CredentialSubject,
	}
	if vc.CredentialStatus != nil {
		m["credentialStatus"] = vc.CredentialStatus
	}
	return deterministicJSON(m)
}

// canonicalizePresentation creates a deterministic byte representation of a VP (omitting proof).
func canonicalizePresentation(vp *VerifiablePresentation) ([]byte, error) {
	m := map[string]interface{}{
		"@context":             vp.Context,
		"id":                   vp.ID,
		"type":                 vp.Type,
		"verifiableCredential": vp.VerifiableCredential,
		"holder":               vp.Holder,
	}
	return deterministicJSON(m)
}

func deterministicJSON(v interface{}) ([]byte, error) {
	data, err := json.Marshal(v)
	if err != nil {
		return nil, err
	}
	var raw interface{}
	if err := json.Unmarshal(data, &raw); err != nil {
		return nil, err
	}
	normalized := sortJSON(raw)
	canonicalBytes, err := json.Marshal(normalized)
	if err != nil {
		return nil, err
	}
	hash := sha256.Sum256(canonicalBytes)
	return hash[:], nil
}

func sortJSON(val interface{}) interface{} {
	switch v := val.(type) {
	case map[string]interface{}:
		sortedMap := make(map[string]interface{})
		keys := make([]string, 0, len(v))
		for k := range v {
			keys = append(keys, k)
		}
		sort.Strings(keys)
		for _, k := range keys {
			sortedMap[k] = sortJSON(v[k])
		}
		return sortedMap
	case []interface{}:
		sortedArr := make([]interface, len(v))
		for i, elem := range v {
			sortedArr[i] = sortJSON(elem)
		}
		return sortedArr
	default:
		return v
	}
}

func stringsIndex(s, substr string) int {
	for i := 0; i+len(substr) <= len(s); i++ {
		if s[i:i+len(substr)] == substr {
			return i
		}
	}
	return 0
}
