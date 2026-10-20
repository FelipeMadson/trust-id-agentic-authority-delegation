// Package audit implements a cryptographically chained Merkle Audit Tree
// providing tamper-evident forensic logging and cryptographic non-repudiation
// for Autonomous Agent actions in RNP Scientific Data Spaces.
package audit

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"sync"
	"time"
)

// AuditRecord models an immutable forensic event log entry for an agent operation.
type AuditRecord struct {
	RecordID     string `json:"recordId"`
	AgentDID     string `json:"agentDid"`
	PrincipalDID string `json:"principalDid"`
	Dataspace    string `json:"dataspace"`
	Action       string `json:"action"`
	ResourceID   string `json:"resourceId"`
	Decision     bool   `json:"decision"`
	Timestamp    string `json:"timestamp"`
	Signature    string `json:"signature,omitempty"`
	LeafHash     string `json:"leafHash"`
}

// ProofStep represents a sibling node in the Merkle path.
type ProofStep struct {
	SiblingHash string `json:"siblingHash"`
	IsRight     bool   `json:"isRight"`
}

// InclusionProof provides the cryptographic path verifying that a specific record
// is present inside the immutable Merkle Root without revealing the entire dataset.
type InclusionProof struct {
	RecordID  string      `json:"recordId"`
	LeafHash  string      `json:"leafHash"`
	RootHash  string      `json:"rootHash"`
	TreeSize  int         `json:"treeSize"`
	LeafIndex int         `json:"leafIndex"`
	AuditPath []ProofStep `json:"auditPath"`
}

// MerkleAuditTree represents an append-only cryptographic Merkle Tree.
type MerkleAuditTree struct {
	mu      sync.RWMutex
	records []*AuditRecord
	leaves  [][]byte
	root    []byte
}

// NewMerkleAuditTree creates a new empty Merkle Audit Tree.
func NewMerkleAuditTree() *MerkleAuditTree {
	return &MerkleAuditTree{
		records: make([]*AuditRecord, 0),
		leaves:  make([][]byte, 0),
		root:    nil,
	}
}

// AppendRecord registers a new audit event, computes its SHA-256 leaf hash,
// appends it to the tree, and recalculates the Merkle Root.
func (t *MerkleAuditTree) AppendRecord(
	recordID string,
	agentDID string,
	principalDID string,
	dataspace string,
	action string,
	resourceID string,
	decision bool,
	sig string,
) (*AuditRecord, string, error) {
	t.mu.Lock()
	defer t.mu.Unlock()

	rec := &AuditRecord{
		RecordID:     recordID,
		AgentDID:     agentDID,
		PrincipalDID: principalDID,
		Dataspace:    dataspace,
		Action:       action,
		ResourceID:   resourceID,
		Decision:     decision,
		Timestamp:    time.Now().UTC().Format(time.RFC3339Nano),
		Signature:    sig,
	}

	leafHashBytes, err := computeLeafHash(rec)
	if err != nil {
		return nil, "", fmt.Errorf("failed to compute leaf hash: %w", err)
	}
	rec.LeafHash = hex.EncodeToString(leafHashBytes)

	t.records = append(t.records, rec)
	t.leaves = append(t.leaves, leafHashBytes)
	t.root = t.recalculateRoot()

	return rec, hex.EncodeToString(t.root), nil
}

// GetCurrentRoot returns the current hex-encoded Merkle Root hash.
func (t *MerkleAuditTree) GetCurrentRoot() string {
	t.mu.RLock()
	defer t.mu.RUnlock()
	if t.root == nil {
		return ""
	}
	return hex.EncodeToString(t.root)
}

// Size returns the count of records in the tree.
func (t *MerkleAuditTree) Size() int {
	t.mu.RLock()
	defer t.mu.RUnlock()
	return len(t.records)
}

// GenerateInclusionProof produces the Merkle audit path for a given record ID.
func (t *MerkleAuditTree) GenerateInclusionProof(recordID string) (*InclusionProof, error) {
	t.mu.RLock()
	defer t.mu.RUnlock()

	idx := -1
	for i, r := range t.records {
		if r.RecordID == recordID {
			idx = i
			break
		}
	}
	if idx == -1 {
		return nil, fmt.Errorf("record with ID '%s' not found in audit log", recordID)
	}

	leafHash := t.leaves[idx]
	treeSize := len(t.leaves)
	path, err := buildAuditPath(t.leaves, idx)
	if err != nil {
		return nil, err
	}

	return &InclusionProof{
		RecordID:  recordID,
		LeafHash:  hex.EncodeToString(leafHash),
		RootHash:  hex.EncodeToString(t.root),
		TreeSize:  treeSize,
		LeafIndex: idx,
		AuditPath: path,
	}, nil
}

// VerifyInclusionProof mathematically evaluates an InclusionProof against the expected RootHash.
func VerifyInclusionProof(proof *InclusionProof) (bool, error) {
	if proof == nil {
		return false, errors.New("proof is nil")
	}

	currentHash, err := hex.DecodeString(proof.LeafHash)
	if err != nil {
		return false, fmt.Errorf("invalid leaf hash hex: %w", err)
	}

	for _, step := range proof.AuditPath {
		siblingHash, err := hex.DecodeString(step.SiblingHash)
		if err != nil {
			return false, fmt.Errorf("invalid sibling hash hex: %w", err)
		}

		var combined []byte
		if step.IsRight {
			// Sibling is on the right
			combined = append(currentHash, siblingHash...)
		} else {
			// Sibling is on the left
			combined = append(siblingHash, currentHash...)
		}
		h := sha256.Sum256(combined)
		currentHash = h[:]
	}

	calculatedRoot := hex.EncodeToString(currentHash)
	return calculatedRoot == proof.RootHash, nil
}

func (t *MerkleAuditTree) recalculateRoot() []byte {
	if len(t.leaves) == 0 {
		return nil
	}
	currentLevel := make([][]byte, len(t.leaves))
	copy(currentLevel, t.leaves)

	for len(currentLevel) > 1 {
		var nextLevel [][]byte
		for i := 0; i < len(currentLevel); i += 2 {
			if i+1 < len(currentLevel) {
				combined := append(currentLevel[i], currentLevel[i+1]...)
				h := sha256.Sum256(combined)
				nextLevel = append(nextLevel, h[:])
			} else {
				// Odd node is duplicated to balance the tree (RFC 6962 / Bitcoin standard)
				combined := append(currentLevel[i], currentLevel[i]...)
				h := sha256.Sum256(combined)
				nextLevel = append(nextLevel, h[:])
			}
		}
		currentLevel = nextLevel
	}

	return currentLevel[0]
}

func buildAuditPath(leaves [][]byte, targetIdx int) ([]ProofStep, error) {
	if len(leaves) == 0 || targetIdx < 0 || targetIdx >= len(leaves) {
		return nil, errors.New("invalid leaves or index")
	}

	var path []ProofStep
	currentLevel := make([][]byte, len(leaves))
	copy(currentLevel, leaves)
	currIdx := targetIdx

	for len(currentLevel) > 1 {
		var sibling []byte
		var isRight bool

		if currIdx%2 == 0 {
			// Current node is on the left; sibling is on the right
			if currIdx+1 < len(currentLevel) {
				sibling = currentLevel[currIdx+1]
			} else {
				sibling = currentLevel[currIdx] // duplicate if odd
			}
			isRight = true
		} else {
			// Current node is on the right; sibling is on the left
			sibling = currentLevel[currIdx-1]
			isRight = false
		}

		path = append(path, ProofStep{
			SiblingHash: hex.EncodeToString(sibling),
			IsRight:     isRight,
		})

		// Move to parent level
		var nextLevel [][]byte
		for i := 0; i < len(currentLevel); i += 2 {
			if i+1 < len(currentLevel) {
				combined := append(currentLevel[i], currentLevel[i+1]...)
				h := sha256.Sum256(combined)
				nextLevel = append(nextLevel, h[:])
			} else {
				combined := append(currentLevel[i], currentLevel[i]...)
				h := sha256.Sum256(combined)
				nextLevel = append(nextLevel, h[:])
			}
		}
		currentLevel = nextLevel
		currIdx /= 2
	}

	return path, nil
}

func computeLeafHash(rec *AuditRecord) ([]byte, error) {
	// Canonical payload for leaf hashing (RFC 6962 standard leaf prefix: 0x00)
	m := map[string]interface{}{
		"recordId":     rec.RecordID,
		"agentDid":     rec.AgentDID,
		"principalDid": rec.PrincipalDID,
		"dataspace":    rec.Dataspace,
		"action":       rec.Action,
		"resourceId":   rec.ResourceID,
		"decision":     rec.Decision,
		"timestamp":    rec.Timestamp,
		"signature":    rec.Signature,
	}
	data, err := json.Marshal(m)
	if err != nil {
		return nil, err
	}
	prefix := []byte{0x00} // RFC 6962 leaf domain separator to prevent second-preimage attacks
	h := sha256.Sum256(append(prefix, data...))
	return h[:], nil
}
