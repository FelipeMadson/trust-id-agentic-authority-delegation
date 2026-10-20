// Command server starts the TRUST-ID microservice daemon for RNP Scientific Data Spaces.
package main

import (
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"os/signal"
	"syscall"
	"time"

	"github.com/FelipeMadson/trust-id-agentic-authority-delegation/pkg/audit"
	"github.com/FelipeMadson/trust-id-agentic-authority-delegation/pkg/credentials"
	"github.com/FelipeMadson/trust-id-agentic-authority-delegation/pkg/delegation"
	"github.com/FelipeMadson/trust-id-agentic-authority-delegation/pkg/identity"
	"github.com/FelipeMadson/trust-id-agentic-authority-delegation/pkg/policy"
)

type Server struct {
	identityReg *identity.IdentityRegistry
	revocation  *credentials.RevocationRegistry
	policyEng   *policy.PolicyEngine
	auditTree   *audit.MerkleAuditTree
}

func NewServer() *Server {
	return &Server{
		identityReg: identity.NewIdentityRegistry(),
		revocation:  credentials.NewRevocationRegistry("https://trust-id.rnp.br/status/2026/1"),
		policyEng:   policy.NewPolicyEngine(),
		auditTree:   audit.NewMerkleAuditTree(),
	}
}

func main() {
	port := os.Getenv("PORT")
	if port == "" {
		port = "8084"
	}

	srv := NewServer()

	// Pre-seed a known Human Principal for demonstration
	humanKP, _, err := srv.identityReg.GenerateIdentity("Prof. Dr. Coordenador RNP", identity.TypeHumanPrincipal)
	if err != nil {
		log.Fatalf("failed to seed principal identity: %v", err)
	}
	log.Printf("[TRUST-ID] Pre-seeded Human Principal DID: %s", humanKP.DID)

	mux := http.NewServeMux()

	// Health and Metadata
	mux.HandleFunc("GET /healthz", srv.handleHealth)
	mux.HandleFunc("GET /api/v1/system/info", srv.handleSystemInfo)

	// Identity Management
	mux.HandleFunc("POST /api/v1/identity/generate", srv.handleGenerateIdentity)
	mux.HandleFunc("POST /api/v1/identity/resolve", srv.handleResolveIdentity)

	// Verifiable Credentials
	mux.HandleFunc("POST /api/v1/credentials/issue", srv.handleIssueCredential)
	mux.HandleFunc("POST /api/v1/credentials/verify", srv.handleVerifyCredential)

	// Authority Delegation
	mux.HandleFunc("POST /api/v1/delegation/chain/create", srv.handleCreateDelegationChain)
	mux.HandleFunc("POST /api/v1/delegation/chain/verify", srv.handleVerifyDelegationChain)

	// Policy Evaluation
	mux.HandleFunc("POST /api/v1/policy/evaluate", srv.handlePolicyEvaluate)

	// Merkle Audit Logging
	mux.HandleFunc("POST /api/v1/audit/record", srv.handleAuditRecord)
	mux.HandleFunc("GET /api/v1/audit/proof", srv.handleAuditProof)
	mux.HandleFunc("POST /api/v1/audit/verify-proof", srv.handleVerifyAuditProof)
	mux.HandleFunc("GET /api/v1/audit/root", srv.handleAuditRoot)

	handler := enableCORS(mux)

	httpServer := &http.Server{
		Addr:         ":" + port,
		Handler:      handler,
		ReadTimeout:  10 * time.Second,
		WriteTimeout: 15 * time.Second,
	}

	go func() {
		log.Printf("[TRUST-ID] Listening on http://0.0.0.0:%s", port)
		if err := httpServer.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			log.Fatalf("[TRUST-ID] Server error: %v", err)
		}
	}()

	quit := make(chan os.Signal, 1)
	signal.Notify(quit, syscall.SIGINT, syscall.SIGTERM)
	<-quit
	log.Println("[TRUST-ID] Shutting down gracefully...")
}

func (s *Server) handleHealth(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"status":    "healthy",
		"service":   "trust-id-agentic-authority-delegation",
		"version":   "1.0.0",
		"timestamp": time.Now().UTC().Format(time.RFC3339),
		"project":   "RNP Chamada PCI 2026 - Projeto 4 TRUST-ID",
	})
}

func (s *Server) handleSystemInfo(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"name":            "TRUST-ID Reference Daemon",
		"specification":   "W3C DID Core 1.0, W3C VC 2.0, RFC 6962 Merkle Tree, OPA Rego",
		"targetFramework": "RNP DPDI Scientific Data Spaces",
		"auditTreeSize":   s.auditTree.Size(),
		"merkleRoot":      s.auditTree.GetCurrentRoot(),
	})
}

func (s *Server) handleGenerateIdentity(w http.ResponseWriter, r *http.Request) {
	var body struct {
		Label     string             `json:"label"`
		AgentType identity.AgentType `json:"agentType"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}
	if body.AgentType == "" {
		body.AgentType = identity.TypeWorkerAgent
	}

	kp, doc, err := s.identityReg.GenerateIdentity(body.Label, body.AgentType)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"did":         kp.DID,
		"label":       kp.Label,
		"agentType":   kp.AgentType,
		"fingerprint": kp.ComputeFingerprint(),
		"didDocument": doc,
	})
}

func (s *Server) handleResolveIdentity(w http.ResponseWriter, r *http.Request) {
	var body struct {
		DID string `json:"did"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	doc, err := s.identityReg.Resolve(body.DID)
	if err != nil {
		respondError(w, http.StatusNotFound, err.Error())
		return
	}
	respondJSON(w, http.StatusOK, doc)
}

func (s *Server) handleIssueCredential(w http.ResponseWriter, r *http.Request) {
	var body struct {
		IssuerDID  string                 `json:"issuerDid"`
		CredID     string                 `json:"credId"`
		CredType   []string               `json:"credType"`
		Subject    map[string]interface{} `json:"subject"`
		TTLSeconds int                    `json:"ttlSeconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	issuerKP, err := s.identityReg.GetKey(body.IssuerDID)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "issuer key not present in local vault: "+err.Error())
		return
	}

	ttl := 24 * time.Hour
	if body.TTLSeconds > 0 {
		ttl = time.Duration(body.TTLSeconds) * time.Second
	}

	vc, err := credentials.IssueCredential(issuerKP, body.CredID, body.CredType, body.Subject, ttl, s.revocation)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, vc)
}

func (s *Server) handleVerifyCredential(w http.ResponseWriter, r *http.Request) {
	var body credentials.VerifiableCredential
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondError(w, http.StatusBadRequest, "invalid credential body")
		return
	}

	valid, err := credentials.VerifyCredential(&body, s.identityReg, s.revocation)
	if !valid || err != nil {
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"valid": false,
			"error": fmt.Sprintf("%v", err),
		})
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"valid":   true,
		"message": "Cryptographic signature and revocation status verified successfully",
	})
}

func (s *Server) handleCreateDelegationChain(w http.ResponseWriter, r *http.Request) {
	var body struct {
		PrincipalDID string                     `json:"principalDid"`
		DelegateeDID string                     `json:"delegateeDid"`
		Scope        delegation.PermissionScope `json:"scope"`
		TTLSeconds   int                        `json:"ttlSeconds"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondError(w, http.StatusBadRequest, "invalid request body")
		return
	}

	kp, err := s.identityReg.GetKey(body.PrincipalDID)
	if err != nil {
		respondError(w, http.StatusUnauthorized, "principal key not found in vault: "+err.Error())
		return
	}

	ttl := 12 * time.Hour
	if body.TTLSeconds > 0 {
		ttl = time.Duration(body.TTLSeconds) * time.Second
	}

	chain, err := delegation.NewDelegationChain(kp, body.DelegateeDID, body.Scope, ttl)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, chain)
}

func (s *Server) handleVerifyDelegationChain(w http.ResponseWriter, r *http.Request) {
	var chain delegation.DelegationChain
	if err := json.NewDecoder(r.Body).Decode(&chain); err != nil {
		respondError(w, http.StatusBadRequest, "invalid delegation chain json")
		return
	}

	valid, err := chain.VerifyChain(s.identityReg)
	if !valid || err != nil {
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"valid": false,
			"error": fmt.Sprintf("%v", err),
		})
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"valid":          true,
		"effectiveScope": chain.GetEffectiveScope(),
		"message":        "Delegation chain signatures and monotonic attenuation verified",
	})
}

func (s *Server) handlePolicyEvaluate(w http.ResponseWriter, r *http.Request) {
	var req policy.AccessRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		respondError(w, http.StatusBadRequest, "invalid access request json")
		return
	}

	decision, err := s.policyEng.Evaluate(&req, s.identityReg)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// If granted, automatically record to audit Merkle Tree if obligation requested
	for _, obl := range decision.Obligations {
		if obl.Action == "LOG_MERKLE_AUDIT" {
			principal := req.AgentDID
			if req.DelegationChain != nil {
				principal = req.DelegationChain.RootPrincipalDID
			}
			_, root, _ := s.auditTree.AppendRecord(
				fmt.Sprintf("rec-%d", time.Now().UnixNano()),
				req.AgentDID,
				principal,
				req.Dataspace,
				req.Action,
				req.ResourceID,
				decision.Allow,
				"",
			)
			decision.Reasons = append(decision.Reasons, fmt.Sprintf("Audit event committed to Merkle Root %s", root))
		}
	}

	respondJSON(w, http.StatusOK, decision)
}

func (s *Server) handleAuditRecord(w http.ResponseWriter, r *http.Request) {
	var body struct {
		RecordID     string `json:"recordId"`
		AgentDID     string `json:"agentDid"`
		PrincipalDID string `json:"principalDid"`
		Dataspace    string `json:"dataspace"`
		Action       string `json:"action"`
		ResourceID   string `json:"resourceId"`
		Decision     bool   `json:"decision"`
		Signature    string `json:"signature"`
	}
	if err := json.NewDecoder(r.Body).Decode(&body); err != nil {
		respondError(w, http.StatusBadRequest, "invalid audit record payload")
		return
	}

	rec, root, err := s.auditTree.AppendRecord(
		body.RecordID,
		body.AgentDID,
		body.PrincipalDID,
		body.Dataspace,
		body.Action,
		body.ResourceID,
		body.Decision,
		body.Signature,
	)
	if err != nil {
		respondError(w, http.StatusInternalServerError, err.Error())
		return
	}

	respondJSON(w, http.StatusCreated, map[string]interface{}{
		"record":     rec,
		"merkleRoot": root,
		"treeSize":   s.auditTree.Size(),
	})
}

func (s *Server) handleAuditProof(w http.ResponseWriter, r *http.Request) {
	recordID := r.URL.Query().Get("recordId")
	if recordID == "" {
		respondError(w, http.StatusBadRequest, "missing recordId query parameter")
		return
	}

	proof, err := s.auditTree.GenerateInclusionProof(recordID)
	if err != nil {
		respondError(w, http.StatusNotFound, err.Error())
		return
	}

	respondJSON(w, http.StatusOK, proof)
}

func (s *Server) handleVerifyAuditProof(w http.ResponseWriter, r *http.Request) {
	var proof audit.InclusionProof
	if err := json.NewDecoder(r.Body).Decode(&proof); err != nil {
		respondError(w, http.StatusBadRequest, "invalid proof json")
		return
	}

	valid, err := audit.VerifyInclusionProof(&proof)
	if !valid || err != nil {
		respondJSON(w, http.StatusOK, map[string]interface{}{
			"verified": false,
			"error":    fmt.Sprintf("%v", err),
		})
		return
	}

	respondJSON(w, http.StatusOK, map[string]interface{}{
		"verified": true,
		"message":  "Cryptographic Merkle inclusion proof verified successfully against Root Hash",
	})
}

func (s *Server) handleAuditRoot(w http.ResponseWriter, r *http.Request) {
	respondJSON(w, http.StatusOK, map[string]interface{}{
		"merkleRoot": s.auditTree.GetCurrentRoot(),
		"size":       s.auditTree.Size(),
		"timestamp":  time.Now().UTC().Format(time.RFC3339),
	})
}

func respondJSON(w http.ResponseWriter, status int, data interface{}) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(data)
}

func respondError(w http.ResponseWriter, status int, message string) {
	respondJSON(w, status, map[string]interface{}{
		"error":   message,
		"status":  status,
		"success": false,
	})
}

func enableCORS(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Access-Control-Allow-Origin", "*")
		w.Header().Set("Access-Control-Allow-Methods", "GET, POST, OPTIONS")
		w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
		if r.Method == "OPTIONS" {
			w.WriteHeader(http.StatusOK)
			return
		}
		next.ServeHTTP(w, r)
	})
}
