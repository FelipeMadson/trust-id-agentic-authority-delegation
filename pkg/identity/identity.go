// Package identity implements W3C Decentralized Identifiers (DID Core 1.0)
// specifically optimized for Autonomous AI Agents and Scientific Data Spaces
// under the RNP TRUST-ID architectural framework.
package identity

import (
	"crypto/ed25519"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"
)

// AgentType defines the categorization of actor entities in the TRUST-ID mesh.
type AgentType string

const (
	TypeHumanPrincipal   AgentType = "HumanPrincipal"
	TypeCoordinatorAgent AgentType = "CoordinatorAgent"
	TypeWorkerAgent      AgentType = "WorkerAgent"
	TypeAuditorService   AgentType = "AuditorService"
	TypeDataSpaceGate    AgentType = "DataSpaceGate"
)

// VerificationMethod represents a cryptographic public verification method in W3C DID.
type VerificationMethod struct {
	ID                 string `json:"id"`
	Type               string `json:"type"`
	Controller         string `json:"controller"`
	PublicKeyMultibase string `json:"publicKeyMultibase"`
}

// DIDDocument models a W3C DID Core 1.0 conforming document.
type DIDDocument struct {
	Context              []string             `json:"@context"`
	ID                   string               `json:"id"`
	Controller           string               `json:"controller,omitempty"`
	VerificationMethod   []VerificationMethod `json:"verificationMethod"`
	Authentication       []string             `json:"authentication"`
	AssertionMethod      []string             `json:"assertionMethod"`
	CapabilityDelegation []string             `json:"capabilityDelegation"`
	CapabilityInvocation []string             `json:"capabilityInvocation"`
	Created              string               `json:"created"`
	Deactivated          bool                 `json:"deactivated"`
}

// KeyPair encapsulates an Ed25519 public/private keypair associated with an entity.
type KeyPair struct {
	PublicKey  ed25519.PublicKey
	PrivateKey ed25519.PrivateKey
	DID        string
	AgentType  AgentType
	Label      string
}

// IdentityRegistry provides an in-memory resolution cache and registry for did:key identifiers.
type IdentityRegistry struct {
	mu        sync.RWMutex
	documents map[string]*DIDDocument
	keys      map[string]*KeyPair
}

// NewIdentityRegistry initializes a concurrent identity registry.
func NewIdentityRegistry() *IdentityRegistry {
	return &IdentityRegistry{
		documents: make(map[string]*DIDDocument),
		keys:      make(map[string]*KeyPair),
	}
}

// GenerateIdentity creates a new cryptographic keypair, constructs its did:key identifier,
// builds its canonical W3C DID Document, and stores it in the registry.
func (r *IdentityRegistry) GenerateIdentity(label string, agentType AgentType) (*KeyPair, *DIDDocument, error) {
	pub, priv, err := ed25519.GenerateKey(rand.Reader)
	if err != nil {
		return nil, nil, fmt.Errorf("failed to generate ed25519 key: %w", err)
	}

	// did:key encoding for Ed25519 uses multicodec 0xed01 (varint [0xed, 0x01])
	// followed by raw 32-byte public key, prefixed with 'z' (base58btc multibase).
	multicodecKey := append([]byte{0xed, 0x01}, pub...)
	mbKey := "z" + base58Encode(multicodecKey)
	did := "did:key:" + mbKey
	vmID := did + "#" + mbKey

	doc := &DIDDocument{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/ed25519-2020/v1",
		},
		ID: did,
		VerificationMethod: []VerificationMethod{
			{
				ID:                 vmID,
				Type:               "Ed25519VerificationKey2020",
				Controller:         did,
				PublicKeyMultibase: mbKey,
			},
		},
		Authentication:       []string{vmID},
		AssertionMethod:      []string{vmID},
		CapabilityDelegation: []string{vmID},
		CapabilityInvocation: []string{vmID},
		Created:              time.Now().UTC().Format(time.RFC3339),
		Deactivated:          false,
	}

	kp := &KeyPair{
		PublicKey:  pub,
		PrivateKey: priv,
		DID:        did,
		AgentType:  agentType,
		Label:      label,
	}

	r.mu.Lock()
	r.documents[did] = doc
	r.keys[did] = kp
	r.mu.Unlock()

	return kp, doc, nil
}

// Resolve looks up a DID Document by DID identifier.
func (r *IdentityRegistry) Resolve(did string) (*DIDDocument, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	doc, exists := r.documents[did]
	if !exists {
		// Attempt dynamic resolution for did:key
		if strings.HasPrefix(did, "did:key:z") {
			resolvedDoc, err := ResolveDIDKey(did)
			if err != nil {
				return nil, fmt.Errorf("did not found in registry and dynamic resolution failed: %w", err)
			}
			return resolvedDoc, nil
		}
		return nil, errors.New("identity not found in registry")
	}
	if doc.Deactivated {
		return nil, errors.New("identity has been revoked/deactivated")
	}
	return doc, nil
}

// GetKey returns the internal KeyPair for an authorized local agent.
func (r *IdentityRegistry) GetKey(did string) (*KeyPair, error) {
	r.mu.RLock()
	defer r.mu.RUnlock()

	kp, exists := r.keys[did]
	if !exists {
		return nil, errors.New("keypair not found in local vault")
	}
	return kp, nil
}

// ResolveDIDKey performs dynamic deterministic extraction of the public key from a did:key string.
func ResolveDIDKey(did string) (*DIDDocument, error) {
	if !strings.HasPrefix(did, "did:key:z") {
		return nil, errors.New("unsupported DID method: only did:key with base58btc (z) is supported")
	}
	mb := strings.TrimPrefix(did, "did:key:")
	decoded, err := base58Decode(mb[1:]) // strip 'z'
	if err != nil {
		return nil, fmt.Errorf("malformed base58 payload: %w", err)
	}
	if len(decoded) != 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
		return nil, errors.New("invalid multicodec header for ed25519-pub (expected 0xed01)")
	}

	vmID := did + "#" + mb
	return &DIDDocument{
		Context: []string{
			"https://www.w3.org/ns/did/v1",
			"https://w3id.org/security/suites/ed25519-2020/v1",
		},
		ID: did,
		VerificationMethod: []VerificationMethod{
			{
				ID:                 vmID,
				Type:               "Ed25519VerificationKey2020",
				Controller:         did,
				PublicKeyMultibase: mb,
			},
		},
		Authentication:       []string{vmID},
		AssertionMethod:      []string{vmID},
		CapabilityDelegation: []string{vmID},
		CapabilityInvocation: []string{vmID},
		Created:              time.Now().UTC().Format(time.RFC3339),
		Deactivated:          false,
	}, nil
}

// ExtractPublicKey extracts the raw Ed25519 public key bytes from a did:key identifier.
func ExtractPublicKey(did string) (ed25519.PublicKey, error) {
	if !strings.HasPrefix(did, "did:key:z") {
		return nil, errors.New("invalid did:key prefix")
	}
	mb := strings.TrimPrefix(did, "did:key:")
	decoded, err := base58Decode(mb[1:])
	if err != nil {
		return nil, err
	}
	if len(decoded) != 34 || decoded[0] != 0xed || decoded[1] != 0x01 {
		return nil, errors.New("invalid multicodec header")
	}
	return ed25519.PublicKey(decoded[2:]), nil
}

// SignMessage signs a payload using an entity's private key.
func (kp *KeyPair) SignMessage(message []byte) []byte {
	return ed25519.Sign(kp.PrivateKey, message)
}

// VerifySignature validates a signature against the entity's public key.
func VerifySignature(pub ed25519.PublicKey, message, signature []byte) bool {
	return ed25519.Verify(pub, message, signature)
}

// ComputeFingerprint returns the SHA-256 hex string of the public key.
func (kp *KeyPair) ComputeFingerprint() string {
	h := sha256.Sum256(kp.PublicKey)
	return hex.EncodeToString(h[:])
}

// --- Base58btc Implementation (Zero External Dependencies) ---

const b58Alphabet = "123456789ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz"

var b58Map [256]int8

func init() {
	for i := range b58Map {
		b58Map[i] = -1
	}
	for i := 0; i < len(b58Alphabet); i++ {
		b58Map[b58Alphabet[i]] = int8(i)
	}
}

func base58Encode(input []byte) string {
	if len(input) == 0 {
		return ""
	}
	zeros := 0
	for zeros < len(input) && input[zeros] == 0 {
		zeros++
	}

	size := len(input)*138/100 + 1
	buf := make([]byte, size)
	length := 0

	for i := zeros; i < len(input); i++ {
		carry := int(input[i])
		for j := 0; j < length || carry != 0; j++ {
			if j < length {
				carry += int(buf[j]) << 8
			}
			buf[j] = byte(carry % 58)
			carry /= 58
			if j >= length {
				length++
			}
		}
	}

	res := make([]byte, zeros+length)
	for i := 0; i < zeros; i++ {
		res[i] = '1'
	}
	for i := 0; i < length; i++ {
		res[zeros+i] = b58Alphabet[buf[length-1-i]]
	}
	return string(res)
}

func base58Decode(input string) ([]byte, error) {
	if len(input) == 0 {
		return []byte{}, nil
	}
	zeros := 0
	for zeros < len(input) && input[zeros] == '1' {
		zeros++
	}

	buf := make([]byte, len(input))
	length := 0

	for i := zeros; i < len(input); i++ {
		val := b58Map[input[i]]
		if val == -1 {
			return nil, fmt.Errorf("illegal base58 character: %c", input[i])
		}
		carry := int(val)
		for j := 0; j < length || carry != 0; j++ {
			if j < length {
				carry += int(buf[j]) * 58
			}
			buf[j] = byte(carry & 0xff)
			carry >>= 8
			if j >= length {
				length++
			}
		}
	}

	res := make([]byte, zeros+length)
	for i := 0; i < length; i++ {
		res[zeros+i] = buf[length-1-i]
	}
	return res, nil
}
