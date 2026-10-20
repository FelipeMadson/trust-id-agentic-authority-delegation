# TRUST-ID: Decentralized Identity & Cryptographic Authority Delegation for Autonomous AI Agents

[![CI](https://github.com/FelipeMadson/trust-id-agentic-authority-delegation/actions/workflows/ci.yml/badge.svg)](https://github.com/FelipeMadson/trust-id-agentic-authority-delegation/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![Go Report Card](https://goreportcard.com/badge/github.com/FelipeMadson/trust-id-agentic-authority-delegation)](https://goreportcard.com/report/github.com/FelipeMadson/trust-id-agentic-authority-delegation)
[![W3C DID Core 1.0](https://img.shields.io/badge/W3C-DID%20Core%201.0-brightgreen.svg)](https://www.w3.org/TR/did-core/)
[![W3C VC 2.0](https://img.shields.io/badge/W3C-VC%202.0-blueviolet.svg)](https://www.w3.org/TR/vc-data-model-2.0/)

> **Reference Implementation & Research Prototype engineered for RNP DPDI Chamada PCI 2026 — Projeto 4: TRUST-ID (*Modelos de Identidade, Confiança e Delegação de Autoridade para Humanos e Agentes Inteligentes*)**.

---

## 1. Executive Summary

Autonomous AI agents are increasingly tasked with querying, synthesizing, and executing computational workflows across distributed scientific federations (such as Brazilian National Data Spaces and the RNP Ipê backbone). However, delegating authority to autonomous agents introduces critical security risks: **privilege escalation**, **confused deputy attacks**, **unbounded resource exhaustion**, and **lack of forensic non-repudiation**.

**TRUST-ID** provides a production-grade, zero-trust cryptographic fabric designed specifically to address these challenges:
1. **Self-Certifying Agent Identity**: Full conformance with **W3C Decentralized Identifiers (DID Core 1.0)** using `did:key` over Edwards-curve Ed25519 (`0xed01` multicodec), enabling instant offline verification across all participating institutions.
2. **W3C Verifiable Credentials (VC v2.0)**: Cryptographically signed research grants, compute quotas, and attribute credentials with Linked Data Proofs (`Ed25519Signature2020`) and StatusList2021 revocation bitmaps.
3. **Cryptographic Authority Delegation with Monotonic Attenuation**: Multi-hop delegation chains ($\text{Human Principal} \to \text{Coordinator Agent} \to \text{Worker Agent}$) enforcing mathematical invariants: $\text{Scope}(A_{k+1}) \subseteq \text{Scope}(A_k)$, decreasing compute budgets, and non-dilating TTL windows.
4. **OPA/Rego Zero-Trust Policy Engine**: High-performance decision gate evaluating agent requests against dataspace rules, identity assertions, and delegation lineage.
5. **Tamper-Evident Merkle Audit Tree**: Append-only RFC 6962 tree recording all agent actions with domain-separated hashing ($0x00$ leaf prefix) and $O(\log N)$ inclusion proofs for forensic non-repudiation.

---

## 2. Architecture & Mathematical Invariants

```
 +-------------------------------------------------------------------------------+
 |                       Human Principal (Lead Scientist)                        |
 |                         did:key:z6MkuPrincipalKey                             |
 +-------------------------------------------------------------------------------+
                                         |
                                         | Level 0 Delegation (Full Scope, 1000 Credits)
                                         v
 +-------------------------------------------------------------------------------+
 |                        Coordinator Agent (Orchestrator)                       |
 |                        did:key:z6MkuCoordinatorKey                            |
 +-------------------------------------------------------------------------------+
                                         |
                                         | Level 1 Sub-Delegation (Attenuated Scope, 200 Credits)
                                         v
 +-------------------------------------------------------------------------------+
 |                         Worker Agent (Specialist Bot)                         |
 |                          did:key:z6MkuWorkerKey                               |
 +-------------------------------------------------------------------------------+
                                         |
                                         | Signed Action Request + Delegation Chain
                                         v
 +-------------------------------------------------------------------------------+
 |                         Zero-Trust Scientific DataSpace Gate                  |
 |  [Identity Registry] -> [Attenuation Verifier] -> [OPA Engine] -> [Merkle Log]|
 +-------------------------------------------------------------------------------+
```

### Monotonic Attenuation Invariant
For any delegation hop from parent $k$ to child $k+1$:
$$\forall k \ge 0, \quad \mathcal{S}_{k+1} \subseteq \mathcal{S}_k$$
$$C_{k+1} \le C_k \quad (\text{Compute Credits})$$
$$R_{k+1} \le R_k \quad (\text{Max Query Rows})$$
$$T_{\text{exp}}(k+1) \le T_{\text{exp}}(k) \quad (\text{Temporal Expiration Window})$$

---

## 3. REST API Specifications

The server daemon runs on port `8084` with clean RESTful endpoints:

| Endpoint | Method | Description |
|---|---|---|
| `/healthz` | `GET` | Health and readiness probe |
| `/api/v1/system/info` | `GET` | System capabilities and active Merkle Root |
| `/api/v1/identity/generate` | `POST` | Generates Ed25519 keypair and W3C `did:key` DID Document |
| `/api/v1/identity/resolve` | `POST` | Resolves `did:key` identifier dynamically or from registry |
| `/api/v1/credentials/issue` | `POST` | Issues signed W3C Verifiable Credential v2.0 |
| `/api/v1/credentials/verify` | `POST` | Verifies cryptographic signature and revocation status |
| `/api/v1/delegation/chain/create` | `POST` | Initializes signed authority delegation chain |
| `/api/v1/delegation/chain/verify` | `POST` | Verifies multi-hop delegation chain and monotonic attenuation |
| `/api/v1/policy/evaluate` | `POST` | Evaluates zero-trust dataspace access policy |
| `/api/v1/audit/record` | `POST` | Appends audited action to the immutable Merkle Tree |
| `/api/v1/audit/proof` | `GET` | Generates $O(\log N)$ cryptographic Merkle inclusion proof |
| `/api/v1/audit/verify-proof` | `POST` | Validates Merkle inclusion proof against current Root Hash |
| `/api/v1/audit/root` | `GET` | Returns current published Merkle Root |

---

## 4. Quickstart

### Using Docker Compose
```bash
docker-compose up -d
curl http://localhost:8084/healthz
```

### Running from Source
```bash
git clone https://github.com/FelipeMadson/trust-id-agentic-authority-delegation.git
cd trust-id-agentic-authority-delegation
go test -v -race ./...
go run ./cmd/server
```

---

## 5. Architectural Decision Records (ADRs)
- [ADR-001: W3C DID Core & Verifiable Credentials Selection](docs/adr/ADR-001-w3c-did-vc-agent-identity.md)
- [ADR-002: Monotonic Attenuation & OPA Policy Evaluation Engine](docs/adr/ADR-002-opa-policy-engine-delegation.md)
- [ADR-003: Tamper-Evident Merkle Audit Tree for Agent Non-Repudiation](docs/adr/ADR-003-merkle-audit-scientific-dataspaces.md)

---

## 6. Academic Citation & Attribution

```bibtex
@misc{madson2026trustid,
  author = {Felipe Madison},
  title = {TRUST-ID: Decentralized Identity, Attenuated Delegation, and Cryptographic Merkle Audit Trails for Autonomous Agentic AI in Scientific Data Spaces},
  year = {2026},
  publisher = {GitHub},
  howpublished = {\url{https://github.com/FelipeMadson/trust-id-agentic-authority-delegation}},
  note = {RNP DPDI Chamada PCI 2026 - Reference Architecture}
}
```

## License
MIT License (c) 2026 Felipe Madison.
