# TRUST-ID: Identidade Descentralizada e Delegação Criptográfica de Autoridade para Agentes Autônomos de IA

[![CI](https://github.com/FelipeMadson/trust-id-agentic-authority-delegation/actions/workflows/ci.yml/badge.svg)](https://github.com/FelipeMadson/trust-id-agentic-authority-delegation/actions)
[![License: MIT](https://img.shields.io/badge/License-MIT-blue.svg)](LICENSE)
[![W3C DID Core 1.0](https://img.shields.io/badge/W3C-DID%20Core%201.0-brightgreen.svg)](https://www.w3.org/TR/did-core/)
[![W3C VC 2.0](https://img.shields.io/badge/W3C-VC%202.0-blueviolet.svg)](https://www.w3.org/TR/vc-data-model-2.0/)

> **Implementação de Referência e Protótipo de Pesquisa desenvolvido para a Chamada PCI/CNPq da RNP 2026 — Projeto 4: TRUST-ID (*Modelos de Identidade, Confiança e Delegação de Autoridade para Humanos e Agentes Inteligentes*)**.

---

## 1. Sumário Executivo

Agentes autônomos de inteligência artificial são crescentemente empregados para orquestrar consultas, sintetizar dados e disparar pipelines analíticos em federações científicas distribuídas (como os Data Spaces Nacionais e a infraestrutura de rede da RNP). No entanto, conceder autoridade a agentes de IA sem salvaguardas criptográficas introduz severas vulnerabilidades: **elevação indevida de privilégios**, **ataques do tipo Confused Deputy**, **exaustão descontrolada de recursos computacionais** e **ausência de não-repúdio forense**.

O **TRUST-ID** implementa uma camada zero-trust em nível de produção para mitigar rigorosamente tais riscos:
1. **Identidade Descentralizada e Auto-Certificável**: Aderência estrita à especificação **W3C DID Core 1.0** via método `did:key` sobre curva de Edwards Ed25519 (`0xed01` multicodec), viabilizando resolução determinística sem dependência de terceiros confiáveis.
2. **Credenciais Verificáveis (W3C VC v2.0)**: Emissão e validação de permissões de pesquisa, quotas de cálculo e credenciais acadêmicas com assinaturas criptográficas `Ed25519Signature2020` e verificação de revogação por listas de estado (StatusList2021).
3. **Delegação Criptográfica com Atenuação Monotônica**: Cadeias de delegação multi-hop ($\text{Pesquisador Humano} \to \text{Agente Coordenador} \to \text{Agente Especialista}$) com garantia formal de preservação de invariantes: $\text{Escopo}(A_{k+1}) \subseteq \text{Escopo}(A_k)$, cotas de créditos computacionais decrescentes e janelas de expiração estritas.
4. **Motor de Políticas Zero-Trust compatível com OPA/Rego**: Avaliação em microssensores de decisões de acesso confrontando atributos de identidade, integridade de cadeia e obrigações anexas.
5. **Trilha de Auditoria com Árvore de Merkle Criptográfica**: Log imutável baseado no padrão RFC 6962 com prefixo de separação de domínio ($0x00$) e provas de inclusão criptográfica $O(\log N)$ para perícia forense e auditoria LGPD.

---

## 2. Invariantes Matemáticos de Delegação

```
 +-------------------------------------------------------------------------------+
 |                       Pesquisador Humano (Principal)                          |
 |                         did:key:z6MkuPrincipalKey                             |
 +-------------------------------------------------------------------------------+
                                         |
                                         | Nível 0: Delegação Total (1000 Créditos)
                                         v
 +-------------------------------------------------------------------------------+
 |                        Agente Coordenador (Orquestrador)                      |
 |                        did:key:z6MkuCoordinatorKey                            |
 +-------------------------------------------------------------------------------+
                                         |
                                         | Nível 1: Sub-Delegação Atenuada (200 Créditos)
                                         v
 +-------------------------------------------------------------------------------+
 |                         Agente Especialista (Worker Bot)                      |
 |                          did:key:z6MkuWorkerKey                               |
 +-------------------------------------------------------------------------------+
                                         |
                                         | Requisição Assinada + Cadeia de Delegação
                                         v
 +-------------------------------------------------------------------------------+
 |                     Portal Zero-Trust do Data Space Científico                |
 |  [Registro DID] -> [Validador Atenuado] -> [Motor OPA] -> [Merkle Tree Log]   |
 +-------------------------------------------------------------------------------+
```

### Invariante de Atenuação Monotônica
Para qualquer salto na cadeia de delegação do nó pai $k$ para o filho $k+1$:
$$\forall k \ge 0, \quad \mathcal{S}_{k+1} \subseteq \mathcal{S}_k$$
$$C_{k+1} \le C_k \quad (\text{Créditos Computacionais})$$
$$R_{k+1} \le R_k \quad (\text{Teto de Linhas Retornadas})$$
$$T_{\text{exp}}(k+1) \le T_{\text{exp}}(k) \quad (\text{Janela Temporal de Validade})$$

---

## 3. Endpoints REST da API

O microsserviço opera na porta `8084` provendo uma API REST completa:

| Rota | Método | Descrição |
|---|---|---|
| `/healthz` | `GET` | Verificação de integridade e prontidão do serviço |
| `/api/v1/system/info` | `GET` | Capacidades e estado atual da raiz de Merkle |
| `/api/v1/identity/generate` | `POST` | Gera par de chaves Ed25519 e documento W3C DID |
| `/api/v1/identity/resolve` | `POST` | Resolução determinística de identificador `did:key` |
| `/api/v1/credentials/issue` | `POST` | Emissão de Credencial Verificável W3C v2.0 assinada |
| `/api/v1/credentials/verify` | `POST` | Verificação criptográfica de assinatura e status de revogação |
| `/api/v1/delegation/chain/create` | `POST` | Cria cadeia de delegação inicial a partir do pesquisador humano |
| `/api/v1/delegation/chain/verify` | `POST` | Valida assinaturas e invariantes monotônicos da cadeia de delegação |
| `/api/v1/policy/evaluate` | `POST` | Avalia requisição zero-trust contra regras OPA e escopos delegados |
| `/api/v1/audit/record` | `POST` | Insere evento auditado na Árvore de Merkle imutável |
| `/api/v1/audit/proof` | `GET` | Gera prova criptográfica de inclusão $O(\log N)$ |
| `/api/v1/audit/verify-proof` | `POST` | Valida prova de inclusão de Merkle contra a raiz pública |
| `/api/v1/audit/root` | `GET` | Retorna o hash da raiz de Merkle atual |

---

## 4. Como Executar

### Via Docker Compose
```bash
docker-compose up -d
curl http://localhost:8084/healthz
```

### Compilação e Execução Local
```bash
git clone https://github.com/FelipeMadson/trust-id-agentic-authority-delegation.git
cd trust-id-agentic-authority-delegation
go test -v -race ./...
go run ./cmd/server
```

---

## 5. Registros de Decisão Arquitetural (ADRs)
- [ADR-001: Seleção de W3C DID Core e Credenciais Verificáveis](docs/adr/ADR-001-w3c-did-vc-agent-identity.md)
- [ADR-002: Atenuação Monotônica e Motor de Políticas OPA](docs/adr/ADR-002-opa-policy-engine-delegation.md)
- [ADR-003: Árvore de Auditoria Merkle para Não-Repúdio](docs/adr/ADR-003-merkle-audit-scientific-dataspaces.md)

---

## 6. Citação Acadêmica

```bibtex
@misc{madson2026trustid,
  author = {Felipe Madison},
  title = {TRUST-ID: Identidade Digital Descentralizada, Delegação Criptográfica de Autoridade e Auditoria Merkle para Agentes Autônomos de IA em Data Spaces Científicos},
  year = {2026},
  publisher = {GitHub},
  howpublished = {\url{https://github.com/FelipeMadson/trust-id-agentic-authority-delegation}},
  note = {RNP DPDI Chamada PCI 2026 - Arquitetura de Referência}
}
```

## Licença
Licença MIT (c) 2026 Felipe Madison.
