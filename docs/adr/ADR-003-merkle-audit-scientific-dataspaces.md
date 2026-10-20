# ADR-003: Tamper-Evident Merkle Audit Tree for Scientific Agent Non-Repudiation

## Status
Accepted

## Context
Autonomous agents performing data querying, data transformation, and model training in academic federations require strict legal and ethical accountability (LGPD, scientific reproducibility, and data custody auditing). Traditional centralized database audit logs are susceptible to retroactive tampering, deletion, or rogue administrator modification.

## Decision
We implement an append-only **Cryptographic Merkle Audit Tree** adhering to RFC 6962 standards:
1. **Domain Separated Leaf Hashing**: Each audit log entry is hashed with a `0x00` leaf prefix to prevent second-preimage collision attacks:
   $$\text{LeafHash} = \text{SHA-256}(0x00 \parallel \text{CanonicalJSON}(\text{AuditRecord}))$$
2. **Deterministic Tree Aggregation**: Internal nodes are hashed with `0x01` prefix:
   $$\text{NodeHash} = \text{SHA-256}(0x01 \parallel \text{LeftChild} \parallel \text{RightChild})$$
3. **Cryptographic Inclusion Proofs**: Any external auditor or participating scientific institution can request an $O(\log N)$ inclusion proof for any transaction. Verification requires only the leaf hash, the audit path, and the published Merkle Root.

## Consequences
### Positive
- Mathematically guarantees tamper evidence: any retroactive modification invalidates the public Merkle Root.
- Compact inclusion proofs ($O(\log N)$) enable trust verification without disclosing other tenant logs.
- Ready for periodic anchoring to public blockchain observatories (e.g. RNP Observatório Nacional de Blockchain / Projeto 3).
