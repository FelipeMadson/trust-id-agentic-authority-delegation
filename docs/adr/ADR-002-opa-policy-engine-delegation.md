# ADR-002: Monotonic Attenuation & OPA-Compatible Policy Evaluation Engine

## Status
Accepted

## Context
In scientific data spaces (e.g., genomics, epidemiology, biodiversity, climate monitoring), autonomous multi-agent systems must execute complex data pipelines. When a human principal (e.g., Lead Scientist) delegates tasks to an orchestrator agent, which in turn spawns specialized worker agents, there is an inherent risk of **privilege escalation**, **delegation hijacking**, or **excessive resource consumption**.

Static Role-Based Access Control (RBAC) is insufficient to model dynamic multi-agent delegation chains.

## Decision
We implement a **Cryptographic Monotonic Attenuation Engine** integrated with an **Open Policy Agent (OPA) / Rego compatible rule evaluation engine**:
1. **Monotonic Invariant**: At each hop $k \to k+1$ in the delegation chain, the authority scope must satisfy:
   $$\text{Scope}(A_{k+1}) \subseteq \text{Scope}(A_k)$$
   $$\text{MaxComputeCredits}(A_{k+1}) \le \text{MaxComputeCredits}(A_k)$$
   $$\text{MaxQueryRows}(A_{k+1}) \le \text{MaxQueryRows}(A_k)$$
   $$\text{ExpiresAt}(A_{k+1}) \le \text{ExpiresAt}(A_k)$$
2. **Cryptographic Chaining**: Each delegation node contains the SHA-256 hash of its parent node and is signed by the delegator's Ed25519 private key.
3. **Zero-Trust Policy Gate**: Before any scientific resource is accessed, the policy engine verifies the full delegation chain, checks active revocation status, evaluates attribute-based access control (ABAC) rules, and attaches mandatory obligations (such as Merkle audit logging and credit metering).

## Consequences
### Positive
- Formally guarantees that sub-agents can never possess broader authority than their coordinators.
- Eliminates Confused Deputy attacks in multi-agent workflows.
- Fully compatible with cloud-native Open Policy Agent (OPA) admission controllers.

### Negative / Trade-offs
- Verification cost scales linearly with delegation depth $O(N)$ where $N$ is the chain length. Capped at $N \le 5$ in production configurations.
