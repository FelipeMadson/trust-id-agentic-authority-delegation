# ADR-001: W3C DID Core and Verifiable Credentials Selection for Agentic AI Identity

## Status
Accepted

## Context
Under the RNP Chamada PCI 2026 (Projeto 4: TRUST-ID - Modelos de Identidade, Confiança e Delegação de Autoridade para Humanos e Agentes Inteligentes), autonomous AI agents require cryptographically verifiable identities capable of interacting across heterogeneous scientific federations (such as Brazilian National Data Spaces and the RNP Ipê backbone). 

Traditional centralized identity protocols (e.g. static API tokens or bearer JWTs) suffer from significant architectural flaws:
1. Vulnerability to single-point-of-failure identity providers.
2. Lack of self-certifying public keys.
3. Inability to cryptographically decouple identity registration from cross-federation verification.

## Decision
We adopt the **W3C Decentralized Identifiers (DID Core 1.0)** standard leveraging the `did:key` method combined with the **W3C Verifiable Credentials Data Model v2.0**.
- **Cryptographic Suite**: `Ed25519VerificationKey2020` utilizing 256-bit Edwards-curve Digital Signature Algorithm (Ed25519) with multicodec prefix `0xed01` and base58btc (`z`) encoding.
- **Self-Certifying DIDs**: `did:key` allows any verifier in the RNP data space to derive the agent's public key directly from the identifier without requiring an online blockchain query or centralized directory lookup.
- **Verifiable Credentials & Presentations**: Granular capabilities (research permissions, computational resource quotas) are issued by human principal authorities as signed JSON-LD / JCS credentials. Agents package these into Verifiable Presentations signed with their private keys.

## Consequences
### Positive
- Zero external network dependency for DID resolution (deterministic extraction of public keys).
- Conformance with international scientific data space standards (Gaia-X, IDS, W3C).
- Instant verification latency (< 0.2ms per signature check).

### Negative / Trade-offs
- Key rotation requires issuing a new `did:key` identifier. For long-lived organizational roots, future extensions can support `did:ion` or `did:web` resolution.
