// Package policy implements a Rego/Open Policy Agent (OPA) style policy evaluation engine
// tailored for Zero-Trust Scientific Data Spaces in the RNP TRUST-ID architecture.
package policy

import (
	"errors"
	"fmt"
	"strings"
	"sync"
	"time"

	"github.com/FelipeMadson/trust-id-agentic-authority-delegation/pkg/delegation"
	"github.com/FelipeMadson/trust-id-agentic-authority-delegation/pkg/identity"
)

// AccessRequest encapsulates the context of an agent requesting an operation on a scientific asset.
type AccessRequest struct {
	AgentDID        string                      `json:"agentDid"`
	AgentType       identity.AgentType          `json:"agentType"`
	Dataspace       string                      `json:"dataspace"`
	ResourceID      string                      `json:"resourceId"`
	Action          string                      `json:"action"` // "READ", "QUERY", "EXECUTE_PIPELINE", "EXPORT"
	RequestedRows   int                         `json:"requestedRows"`
	RequestedCredit int                         `json:"requestedCredit"`
	DelegationChain *delegation.DelegationChain `json:"delegationChain,omitempty"`
}

// Obligation describes a mandatory side-effect or security requirement enforced upon policy grant.
type Obligation struct {
	Action     string            `json:"action"` // e.g. "LOG_MERKLE_AUDIT", "METER_COMPUTE_CREDITS", "ANONYMIZE_PII"
	Parameters map[string]string `json:"parameters"`
}

// Decision represents the final evaluation verdict.
type Decision struct {
	Allow       bool         `json:"allow"`
	Reasons     []string     `json:"reasons"`
	Obligations []Obligation `json:"obligations"`
	EvaluatedAt string       `json:"evaluatedAt"`
}

// PolicyRule defines an individual authorization policy rule.
type PolicyRule struct {
	ID                  string               `json:"id"`
	Description         string               `json:"description"`
	TargetDataspace     string               `json:"targetDataspace"` // wildcard "*" supported
	AllowedActions      []string             `json:"allowedActions"`
	AllowedAgentTypes   []identity.AgentType `json:"allowedAgentTypes"`
	MaxDelegationDepth  int                  `json:"maxDelegationDepth"`
	RequireDelegation   bool                 `json:"requireDelegation"`
	EnforceDataEgress   bool                 `json:"enforceDataEgress"`
	MaxAllowedRows      int                  `json:"maxAllowedRows"`
	RequiredObligations []string             `json:"requiredObligations"`
}

// PolicyEngine stores rules and executes zero-trust policy decisions.
type PolicyEngine struct {
	mu    sync.RWMutex
	rules map[string]PolicyRule
}

// NewPolicyEngine initializes the OPA-style policy engine with default scientific dataspace baseline rules.
func NewPolicyEngine() *PolicyEngine {
	pe := &PolicyEngine{
		rules: make(map[string]PolicyRule),
	}
	pe.loadDefaultScientificRules()
	return pe
}

// AddRule registers a new rule in the policy engine.
func (pe *PolicyEngine) AddRule(rule PolicyRule) {
	pe.mu.Lock()
	defer pe.mu.Unlock()
	pe.rules[rule.ID] = rule
}

// Evaluate processes an AccessRequest against all applicable policies and delegation scopes.
func (pe *PolicyEngine) Evaluate(req *AccessRequest, reg *identity.IdentityRegistry) (*Decision, error) {
	pe.mu.RLock()
	defer pe.mu.RUnlock()

	dec := &Decision{
		Allow:       false,
		Reasons:     []string{},
		Obligations: []Obligation{},
		EvaluatedAt: time.Now().UTC().Format(time.RFC3339),
	}

	if req == nil {
		return nil, errors.New("nil access request")
	}

	// 1. Verify Agent Identity exists in registry
	doc, err := reg.Resolve(req.AgentDID)
	if err != nil {
		dec.Reasons = append(dec.Reasons, fmt.Sprintf("Identity resolution failed for %s: %v", req.AgentDID, err))
		return dec, nil
	}
	if doc.Deactivated {
		dec.Reasons = append(dec.Reasons, fmt.Sprintf("Agent identity %s is deactivated", req.AgentDID))
		return dec, nil
	}

	// 2. If a delegation chain is present, verify its cryptographic integrity
	if req.DelegationChain != nil {
		valid, err := req.DelegationChain.VerifyChain(reg)
		if !valid || err != nil {
			dec.Reasons = append(dec.Reasons, fmt.Sprintf("Delegation chain cryptographic verification failed: %v", err))
			return dec, nil
		}
		if req.DelegationChain.LeafAgentDID != req.AgentDID {
			dec.Reasons = append(dec.Reasons, fmt.Sprintf("Delegation leaf agent %s does not match request agent %s",
				req.DelegationChain.LeafAgentDID, req.AgentDID))
			return dec, nil
		}
	}

	// 3. Find matching policy rules for the targeted dataspace
	var matchingRules []PolicyRule
	for _, r := range pe.rules {
		if r.TargetDataspace == "*" || r.TargetDataspace == req.Dataspace || strings.HasPrefix(req.Dataspace, r.TargetDataspace) {
			matchingRules = append(matchingRules, r)
		}
	}

	if len(matchingRules) == 0 {
		dec.Reasons = append(dec.Reasons, fmt.Sprintf("No policy rule defined for dataspace '%s' (Default Deny)", req.Dataspace))
		return dec, nil
	}

	// 4. Evaluate each rule
	for _, rule := range matchingRules {
		// Verify agent type
		typeAllowed := false
		for _, at := range rule.AllowedAgentTypes {
			if at == req.AgentType {
				typeAllowed = true
				break
			}
		}
		if !typeAllowed {
			dec.Reasons = append(dec.Reasons, fmt.Sprintf("Rule %s: AgentType '%s' not authorized for dataspace", rule.ID, req.AgentType))
			continue
		}

		// Verify action
		actionAllowed := false
		for _, a := range rule.AllowedActions {
			if a == "*" || a == req.Action {
				actionAllowed = true
				break
			}
		}
		if !actionAllowed {
			dec.Reasons = append(dec.Reasons, fmt.Sprintf("Rule %s: Action '%s' not authorized", rule.ID, req.Action))
			continue
		}

		// Verify delegation requirement
		if rule.RequireDelegation {
			if req.DelegationChain == nil {
				dec.Reasons = append(dec.Reasons, fmt.Sprintf("Rule %s requires a cryptographic delegation chain", rule.ID))
				continue
			}
			if rule.MaxDelegationDepth > 0 && len(req.DelegationChain.Chain) > rule.MaxDelegationDepth {
				dec.Reasons = append(dec.Reasons, fmt.Sprintf("Rule %s: Delegation depth %d exceeds ceiling of %d",
					rule.ID, len(req.DelegationChain.Chain), rule.MaxDelegationDepth))
				continue
			}

			// Verify delegation scope covers requested action and dataspace
			scope := req.DelegationChain.GetEffectiveScope()
			scopeCoversDS := false
			for _, ds := range scope.AllowedDataspaces {
				if ds == "*" || ds == req.Dataspace {
					scopeCoversDS = true
					break
				}
			}
			if !scopeCoversDS {
				dec.Reasons = append(dec.Reasons, fmt.Sprintf("Rule %s: Delegated scope does not include dataspace '%s'", rule.ID, req.Dataspace))
				continue
			}

			scopeCoversAction := false
			for _, act := range scope.AllowedActions {
				if act == "*" || act == req.Action {
					scopeCoversAction = true
					break
				}
			}
			if !scopeCoversAction {
				dec.Reasons = append(dec.Reasons, fmt.Sprintf("Rule %s: Delegated scope does not include action '%s'", rule.ID, req.Action))
				continue
			}

			// Verify credit limits
			if scope.MaxComputeCredits > 0 && req.RequestedCredit > scope.MaxComputeCredits {
				dec.Reasons = append(dec.Reasons, fmt.Sprintf("Rule %s: Requested compute credits %d exceed delegated budget %d",
					rule.ID, req.RequestedCredit, scope.MaxComputeCredits))
				continue
			}

			// Verify row egress limits
			if scope.MaxQueryRows > 0 && req.RequestedRows > scope.MaxQueryRows {
				dec.Reasons = append(dec.Reasons, fmt.Sprintf("Rule %s: Requested query rows %d exceed delegated limit %d",
					rule.ID, req.RequestedRows, scope.MaxQueryRows))
				continue
			}
		}

		// Verify data egress cap
		if rule.EnforceDataEgress && rule.MaxAllowedRows > 0 && req.RequestedRows > rule.MaxAllowedRows {
			dec.Reasons = append(dec.Reasons, fmt.Sprintf("Rule %s: Egress query rows %d exceed dataspace cap %d",
				rule.ID, req.RequestedRows, rule.MaxAllowedRows))
			continue
		}

		// Rule fully satisfied: Grant Access and collect obligations
		dec.Allow = true
		dec.Reasons = []string{fmt.Sprintf("Access Granted by Policy Rule '%s' (%s)", rule.ID, rule.Description)}
		for _, obl := range rule.RequiredObligations {
			dec.Obligations = append(dec.Obligations, Obligation{
				Action: obl,
				Parameters: map[string]string{
					"agentDid":   req.AgentDID,
					"dataspace":  req.Dataspace,
					"resourceId": req.ResourceID,
					"action":     req.Action,
				},
			})
		}
		return dec, nil
	}

	return dec, nil
}

func (pe *PolicyEngine) loadDefaultScientificRules() {
	// Rule 1: Genomics Research Dataspace Access
	pe.rules["rule-genomics-research"] = PolicyRule{
		ID:                 "rule-genomics-research",
		Description:        "Authorizes Worker and Coordinator Agents to query genomic datasets under verified delegation",
		TargetDataspace:    "br.rnp.dataspace.genomics",
		AllowedActions:     []string{"READ", "QUERY", "ANALYZE"},
		AllowedAgentTypes:  []identity.AgentType{identity.TypeCoordinatorAgent, identity.TypeWorkerAgent},
		MaxDelegationDepth: 3,
		RequireDelegation:  true,
		EnforceDataEgress:  true,
		MaxAllowedRows:     50000,
		RequiredObligations: []string{
			"LOG_MERKLE_AUDIT",
			"METER_COMPUTE_CREDITS",
			"ANONYMIZE_GENOMIC_IDENTIFIERS",
		},
	}

	// Rule 2: Climate & Biodiversity DataSpace
	pe.rules["rule-climate-biodiversity"] = PolicyRule{
		ID:                 "rule-climate-biodiversity",
		Description:        "Open scientific telemetry query with full audit trail",
		TargetDataspace:    "br.rnp.dataspace.climate",
		AllowedActions:     []string{"READ", "QUERY", "EXECUTE_PIPELINE"},
		AllowedAgentTypes:  []identity.AgentType{identity.TypeCoordinatorAgent, identity.TypeWorkerAgent, identity.TypeHumanPrincipal},
		MaxDelegationDepth: 5,
		RequireDelegation:  false,
		EnforceDataEgress:  true,
		MaxAllowedRows:     100000,
		RequiredObligations: []string{
			"LOG_MERKLE_AUDIT",
		},
	}

	// Rule 3: High-Performance Computing (HPC) Execution Gate
	pe.rules["rule-hpc-pipeline"] = PolicyRule{
		ID:                 "rule-hpc-pipeline",
		Description:        "Strict delegation gate for triggering remote scientific pipeline compute",
		TargetDataspace:    "br.rnp.dataspace.hpc",
		AllowedActions:     []string{"EXECUTE_PIPELINE"},
		AllowedAgentTypes:  []identity.AgentType{identity.TypeCoordinatorAgent},
		MaxDelegationDepth: 2,
		RequireDelegation:  true,
		EnforceDataEgress:  false,
		RequiredObligations: []string{
			"LOG_MERKLE_AUDIT",
			"METER_COMPUTE_CREDITS",
			"REQUIRE_SANDBOX_ISOLATION",
		},
	}
}
