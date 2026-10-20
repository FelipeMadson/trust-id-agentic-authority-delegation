// Package delegation implements cryptographic authority delegation chains with
// monotonic attenuation (rights, resource budgets, operations, and temporal windows)
// for Autonomous Agentic AI in RNP Scientific Data Spaces.
package delegation

import (
	"crypto/ed25519"
	"crypto/sha256"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"time"

	"github.com/FelipeMadson/trust-id-agentic-authority-delegation/pkg/identity"
)

// PermissionScope defines granular scientific data access parameters.
type PermissionScope struct {
	AllowedDataspaces []string `json:"allowedDataspaces"`
	AllowedActions    []string `json:"allowedActions"`    // e.g. "READ", "QUERY", "EXECUTE_PIPELINE", "ANALYZE", "EXPORT"
	MaxComputeCredits int      `json:"maxComputeCredits"` // Resource consumption limit
	MaxQueryRows      int      `json:"maxQueryRows"`      // Privacy & egress limit
}

// DelegationNode represents a single signed delegation link in the authority chain.
type DelegationNode struct {
	DelegatorDID   string          `json:"delegatorDid"`
	DelegateeDID   string          `json:"delegateeDid"`
	Scope          PermissionScope `json:"scope"`
	IssuedAt       string          `json:"issuedAt"`
	ExpiresAt      string          `json:"expiresAt"`
	ParentNodeHash string          `json:"parentNodeHash,omitempty"` // Root node has empty parent
	Signature      string          `json:"signature"`
}

// DelegationChain encapsulates the full cryptographic lineage from Human Principal to executing Agent.
type DelegationChain struct {
	RootPrincipalDID string            `json:"rootPrincipalDid"`
	LeafAgentDID     string            `json:"leafAgentDid"`
	Chain            []*DelegationNode `json:"chain"`
}

// NewDelegationChain initializes a new authority chain with the initial delegation from a Human Principal.
func NewDelegationChain(
	rootKP *identity.KeyPair,
	delegateeDID string,
	scope PermissionScope,
	ttl time.Duration,
) (*DelegationChain, error) {
	now := time.Now().UTC()
	exp := now.Add(ttl)

	rootNode := &DelegationNode{
		DelegatorDID:   rootKP.DID,
		DelegateeDID:   delegateeDID,
		Scope:          scope,
		IssuedAt:       now.Format(time.RFC3339),
		ExpiresAt:      exp.Format(time.RFC3339),
		ParentNodeHash: "",
	}

	payload, err := canonicalNodeBytes(rootNode)
	if err != nil {
		return nil, fmt.Errorf("failed to canonicalize root delegation: %w", err)
	}

	sig := ed25519.Sign(rootKP.PrivateKey, payload)
	rootNode.Signature = base64.RawURLEncoding.EncodeToString(sig)

	return &DelegationChain{
		RootPrincipalDID: rootKP.DID,
		LeafAgentDID:     delegateeDID,
		Chain:            []*DelegationNode{rootNode},
	}, nil
}

// SubDelegate attenuates and extends the delegation chain to a subordinate agent.
// Enforces the Monotonic Attenuation Invariant: the child scope must be a strict subset
// of the parent scope, and expiration must not exceed the parent's expiration.
func (dc *DelegationChain) SubDelegate(
	parentKP *identity.KeyPair,
	subDelegateeDID string,
	attenuatedScope PermissionScope,
	ttl time.Duration,
) error {
	if len(dc.Chain) == 0 {
		return errors.New("cannot sub-delegate from an empty chain")
	}

	lastNode := dc.Chain[len(dc.Chain)-1]
	if lastNode.DelegateeDID != parentKP.DID {
		return fmt.Errorf("parent key does not match current chain leaf (expected %s, got %s)",
			lastNode.DelegateeDID, parentKP.DID)
	}

	now := time.Now().UTC()
	requestedExp := now.Add(ttl)
	parentExp, err := time.Parse(time.RFC3339, lastNode.ExpiresAt)
	if err != nil {
		return fmt.Errorf("failed to parse parent expiration: %w", err)
	}

	if requestedExp.After(parentExp) {
		return fmt.Errorf("attenuation violation: child expiration (%s) cannot exceed parent expiration (%s)",
			requestedExp.Format(time.RFC3339), parentExp.Format(time.RFC3339))
	}

	// Verify Attenuation Invariants on Scope
	if err := verifyScopeAttenuation(lastNode.Scope, attenuatedScope); err != nil {
		return fmt.Errorf("attenuation invariant rejected: %w", err)
	}

	parentHash := computeNodeHash(lastNode)

	childNode := &DelegationNode{
		DelegatorDID:   parentKP.DID,
		DelegateeDID:   subDelegateeDID,
		Scope:          attenuatedScope,
		IssuedAt:       now.Format(time.RFC3339),
		ExpiresAt:      requestedExp.Format(time.RFC3339),
		ParentNodeHash: parentHash,
	}

	payload, err := canonicalNodeBytes(childNode)
	if err != nil {
		return fmt.Errorf("failed to serialize child node: %w", err)
	}

	sig := ed25519.Sign(parentKP.PrivateKey, payload)
	childNode.Signature = base64.RawURLEncoding.EncodeToString(sig)

	dc.Chain = append(dc.Chain, childNode)
	dc.LeafAgentDID = subDelegateeDID
	return nil
}

// VerifyChain performs end-to-end cryptographic and attenuation verification of the full delegation chain.
func (dc *DelegationChain) VerifyChain(reg *identity.IdentityRegistry) (bool, error) {
	if len(dc.Chain) == 0 {
		return false, errors.New("delegation chain is empty")
	}

	now := time.Now().UTC()
	var prevHash string
	var prevScope PermissionScope
	var prevExp time.Time

	for i, node := range dc.Chain {
		// 1. Verify Parent Hash Linkage
		if i == 0 {
			if node.ParentNodeHash != "" {
				return false, errors.New("root delegation node must have empty ParentNodeHash")
			}
			if node.DelegatorDID != dc.RootPrincipalDID {
				return false, fmt.Errorf("root node delegator mismatch: %s != %s", node.DelegatorDID, dc.RootPrincipalDID)
			}
		} else {
			if node.ParentNodeHash != prevHash {
				return false, fmt.Errorf("broken cryptographic hash link at hop %d", i)
			}
			if node.DelegatorDID != dc.Chain[i-1].DelegateeDID {
				return false, fmt.Errorf("delegator at hop %d (%s) does not match delegatee of hop %d (%s)",
					i, node.DelegatorDID, i-1, dc.Chain[i-1].DelegateeDID)
			}
			// Verify Attenuation
			if err := verifyScopeAttenuation(prevScope, node.Scope); err != nil {
				return false, fmt.Errorf("attenuation violated at hop %d: %w", i, err)
			}
		}

		// 2. Verify Timestamps
		nodeExp, err := time.Parse(time.RFC3339, node.ExpiresAt)
		if err != nil {
			return false, fmt.Errorf("invalid expiresAt at hop %d: %w", i, err)
		}
		if now.After(nodeExp) {
			return false, fmt.Errorf("delegation expired at hop %d", i)
		}
		if i > 0 && nodeExp.After(prevExp) {
			return false, fmt.Errorf("expiration dilation attack at hop %d", i)
		}

		// 3. Verify Cryptographic Signature
		delegatorPub, err := identity.ExtractPublicKey(node.DelegatorDID)
		if err != nil {
			return false, fmt.Errorf("failed to extract delegator public key at hop %d: %w", i, err)
		}

		sig, err := base64.RawURLEncoding.DecodeString(node.Signature)
		if err != nil {
			return false, fmt.Errorf("invalid signature base64 at hop %d: %w", i, err)
		}

		payload, err := canonicalNodeBytes(node)
		if err != nil {
			return false, err
		}

		if !ed25519.Verify(delegatorPub, payload, sig) {
			return false, fmt.Errorf("invalid cryptographic signature at hop %d: delegator %s", i, node.DelegatorDID)
		}

		// Check if delegator DID is deactivated in registry
		doc, err := reg.Resolve(node.DelegatorDID)
		if err == nil && doc.Deactivated {
			return false, fmt.Errorf("delegator identity %s is deactivated/revoked", node.DelegatorDID)
		}

		prevHash = computeNodeHash(node)
		prevScope = node.Scope
		prevExp = nodeExp
	}

	if dc.Chain[len(dc.Chain)-1].DelegateeDID != dc.LeafAgentDID {
		return false, errors.New("leaf agent did does not match last chain delegatee")
	}

	return true, nil
}

// GetEffectiveScope returns the attenuated permissions granted to the leaf agent.
func (dc *DelegationChain) GetEffectiveScope() PermissionScope {
	if len(dc.Chain) == 0 {
		return PermissionScope{}
	}
	return dc.Chain[len(dc.Chain)-1].Scope
}

// verifyScopeAttenuation enforces that child permissions are a strict or equal subset of parent.
func verifyScopeAttenuation(parent, child PermissionScope) error {
	// 1. AllowedDataspaces must be subset
	for _, childDS := range child.AllowedDataspaces {
		found := false
		for _, parentDS := range parent.AllowedDataspaces {
			if childDS == parentDS || parentDS == "*" {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("child requests dataspace '%s' not granted by parent", childDS)
		}
	}

	// 2. AllowedActions must be subset
	for _, childAction := range child.AllowedActions {
		found := false
		for _, parentAction := range parent.AllowedActions {
			if childAction == parentAction || parentAction == "*" {
				found = true
				break
			}
		}
		if !found {
			return fmt.Errorf("child requests action '%s' not granted by parent", childAction)
		}
	}

	// 3. MaxComputeCredits must be <= parent
	if parent.MaxComputeCredits > 0 && child.MaxComputeCredits > parent.MaxComputeCredits {
		return fmt.Errorf("child requested %d compute credits, parent ceiling is %d",
			child.MaxComputeCredits, parent.MaxComputeCredits)
	}

	// 4. MaxQueryRows must be <= parent
	if parent.MaxQueryRows > 0 && child.MaxQueryRows > parent.MaxQueryRows {
		return fmt.Errorf("child requested %d max query rows, parent ceiling is %d",
			child.MaxQueryRows, parent.MaxQueryRows)
	}

	return nil
}

func canonicalNodeBytes(node *DelegationNode) ([]byte, error) {
	// Canonical representation omitting signature
	m := map[string]interface{}{
		"delegatorDid":   node.DelegatorDID,
		"delegateeDid":   node.DelegateeDID,
		"scope":          node.Scope,
		"issuedAt":       node.IssuedAt,
		"expiresAt":      node.ExpiresAt,
		"parentNodeHash": node.ParentNodeHash,
	}
	data, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	h := sha256.Sum256(data)
	return h[:], nil
}

func computeNodeHash(node *DelegationNode) string {
	b, _ := canonicalNodeBytes(node)
	h := sha256.Sum256(append(b, []byte(node.Signature)...))
	return base64.RawURLEncoding.EncodeToString(h[:])
}
