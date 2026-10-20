# DOSSIÊ COMPLETO DE CANDIDATURA — CHAMADA PCI/CNPq DA RNP 2026
**Edital de Chamada Pública nº 02/2026 — RNP / CNPq**  
**Submissão via Sistema JEMS (SBC)**: [https://jems3.sbc.org.br/pci-rnp2026](https://jems3.sbc.org.br/pci-rnp2026)  
**Prazo Fatal de Submissão**: **26/10/2026 às 23h59 (Horário de Brasília)**  
**Candidato**: Felipe Madison  
**Perfil Profissional e de P&D**: Engenheiro de Software Sênior e Pesquisador em Sistemas Distribuídos e Segurança Criptográfica  
**Portfólio Oficial**: [https://felipemadson.github.io/portfolio/](https://felipemadson.github.io/portfolio/)  
**GitHub Principal**: [https://github.com/FelipeMadson](https://github.com/FelipeMadson)

---

## 1. Estratégia de Priorização de Vagas no JEMS

A Chamada PCI 2026 permite a seleção de múltiplas vagas indicando a ordem de preferência. Com base na produção técnica e nos protótipos de referência construídos e publicados, a ordem ótima de inscrição no sistema JEMS é:

### Prioridade 1: Projeto 4 — TRUST-ID
- **Vaga Principal Recomendada**: **Vaga 06 — Desenvolvedor Sênior em Agentes Inteligentes, Autorização e Controle de Acesso** (Bolsa PCI-DC: **R$ 4.394,00/mês**, duração de até 36 meses, 100% remota).
  - *Justificativa de Enquadramento*: Domínio comprovado de Go, Rust e TypeScript; arquitetura de microsserviços REST; especificação W3C DID Core e Verifiable Credentials; Open Policy Agent (OPA/Rego); e autorização Zero-Trust para agentes autônomos. Repositório de comprovação direta: `FelipeMadson/trust-id-agentic-authority-delegation`.
- **Opção Alternativa de Pesquisa**: **Vaga 05 — Pesquisador em Identidade para Agentes Inteligentes** (Bolsa PCI-DB: **R$ 5.408,00/mês**, até 36 meses, 100% remota).
  - *Justificativa de Enquadramento*: Autoria do artigo científico *"TRUST-ID: Arquitetura de Identidade Digital Descentralizada, Delegação Criptográfica com Atenuação Monotônica e Auditoria Merkle para Sistemas Multiagentes Autônomos em Data Spaces Científicos"*, com modelagem formal de SMA e Confiança Zero.
- **Opção Alternativa de Interoperabilidade**: **Vaga 03 — Desenvolvedor Sênior em Credenciais Verificáveis e Interoperabilidade** (Bolsa PCI-DC: **R$ 4.394,00/mês**).
  - *Justificativa de Enquadramento*: Implementação da suíte `Ed25519Signature2020`, canonização RFC 8785 (JCS) e revogação StatusList2021.
- **Opção de Entrada de Alto Impacto**: **Vaga 07 / Vaga 04 — Desenvolvedor Júnior em Testes, Auditoria e Experimentação** (Bolsa PCI-DF: **R$ 1.170,00/mês**).
  - *Justificativa de Enquadramento*: Esteira de CI/CD completa com GitHub Actions, cobertura de testes com detector de corrida (`-race`) e conteinerização Docker.

### Prioridade 2: Projeto 2 — Arquitetura Multidomínio para Redes Quanticamente Seguras
- **Vaga Recomendada**: **Vaga 07 — Desenvolvedor Pleno em Criptografia Pós-Quântica (PQC), QRNG e KMS** (Bolsa PCI-DD: **R$ 3.718,00/mês**, até 36 meses, 100% remota).
  - *Justificativa de Enquadramento*: Implementação de protótipo funcional cobrindo os padrões NIST FIPS 203 (ML-KEM-768), NIST FIPS 204 (ML-DSA-65), encapsulamento híbrido e KMS multidomínio. Repositório: `FelipeMadson/pqc-hybrid-kms-mesh`.
- **Vaga Alternativa**: **Vaga 05 — Desenvolvedor Pleno em QKD, KMS e SDN** (Bolsa PCI-DD: **R$ 3.718,00/mês**).
  - *Justificativa de Enquadramento*: Implementação e validação da interface padronizada ETSI GS QKD 014 para entrega de chaves quânticas.

---

## 2. Memorial Descritivo de Trajetória e Justificativa de Candidatura
*(Texto pronto para cópia e inserção no campo de justificativa / memorial da plataforma JEMS)*

> **Prezados Membros da Comissão de Avaliação RNP / SBC,**
> 
> Apresento minha candidatura às vagas de P&D da Chamada Pública PCI/CNPq/RNP nº 02/2026, com foco de atuação prioritário no **Projeto 4 (TRUST-ID: Modelos de Identidade, Confiança e Delegação de Autoridade para Humanos e Agentes Inteligentes)** e interface direta com o **Projeto 2 (Arquitetura Multidomínio para Redes Quanticamente Seguras)**.
> 
> Minha trajetória profissional e acadêmica fundamenta-se na intersecção entre **engenharia de sistemas distribuídos de alta performance**, **segurança da informação baseada em criptografia aplicada** e **arquiteturas de governança para inteligência artificial**. Ao longo da minha atuação, projetei e publiquei mais de 16 ecossistemas de software de código aberto rigorosamente testados, cobrindo linguagens de programação de sistemas (Rust, Go, C++20, Elixir, TypeScript e Python), com esteiras de integração contínua (CI), verificações formais de invariantes e ausência estrita de vulnerabilidades.
> 
> Em resposta direta aos desafios delineados no Projeto TRUST-ID da RNP, concebi e publiquei como prova de maturidade técnica a implementação de referência **`trust-id-agentic-authority-delegation`** (disponível publicamente em `https://github.com/FelipeMadson/trust-id-agentic-authority-delegation`), que materializa:
> 1. Resolução e geração determinística de identificadores descentralizados no padrão **W3C DID Core 1.0** via método `did:key` sobre curva de Edwards Ed25519 (`0xed01` multicodec).
> 2. Emissão, validação criptográfica e verificação de revogação de **W3C Verifiable Credentials (VC v2.0)** com a suíte `Ed25519Signature2020` e listas comprimidas StatusList2021.
> 3. Um protocolo formal de **Delegação Criptográfica Multi-Salto com Atenuação Monotônica**, no qual privilégios analíticos, tetos de créditos computacionais e janelas temporais de validade decrescem matematicamente de forma estrita em cada salto da cadeia ($\text{Pesquisador Humano} \to \text{Agente Coordenador} \to \text{Agente Trabalhador}$), eliminando vulnerabilidades de *Confused Deputy* e elevação indevida de privilégios em Sistemas Multiagentes.
> 4. Um motor de decisão de acesso Zero-Trust declarativo compatível com **Open Policy Agent (OPA/Rego)** e governança de Data Spaces Científicos.
> 5. Uma **Árvore de Auditoria Merkle (RFC 6962)** com prefixo de separação de domínio para imunidade contra colisões de segunda pré-imagem e geração de provas de inclusão $O(\log N)$, assegurando não-repúdio forense e conformidade com a LGPD.
> 
> Paralelamente, como contribuição ao Projeto 2 da RNP, desenvolvi a solução **`pqc-hybrid-kms-mesh`** (`https://github.com/FelipeMadson/pqc-hybrid-kms-mesh`), aplicando os recentes padrões de Criptografia Pós-Quântica do NIST — **FIPS 203 (ML-KEM-768)** e **FIPS 204 (ML-DSA-65)** — combinados em encapsulamento híbrido com a criptografia clássica X25519 e implementando a interface padronizada internacional **ETSI GS QKD 014** para integração de hardware de Distribuição de Chaves Quânticas.
> 
> Disponho de dedicação integral imediata, experiência consolidada em trabalho remoto colaborativo, fluência em inglês técnico e profundo compromisso em contribuir ativamente para que o Brasil lidere o desenvolvimento de infraestruturas de dados e redes científicas quânticas e agentic-safe.
> 
> Agradeço a avaliação desta comissão examinadora e coloco-me à disposição para a etapa de entrevista técnica.
> 
> **Felipe Madison**

---

## 3. Proposta de Plano de Trabalho Detalhado (12 Meses)

**Título do Plano de Trabalho**: *Implementação e Validação de Infraestrutura Zero-Trust para Identidade Descentralizada, Delegação Atenuada e Auditoria Criptográfica de Agentes Inteligentes nos Data Spaces da RNP*  
**Vínculo**: Projeto 4 (TRUST-ID) com suporte à transição PQC do Projeto 2  
**Carga Horária**: Dedicação conforme edital (100% Remoto)

### Trimestre 1 (Meses 1 a 3): Especificação Formal e Módulo de Identidade W3C DID para Agentes
- **Atividades**:
  - Mapeamento detalhado dos fluxos de interação humano-agente e agente-agente nos pilotos de Data Spaces da RNP (Genômica e Clima).
  - Integração da biblioteca de identificadores W3C DID (`did:key` e extensão para `did:web` institucional) com os provedores de federação acadêmica (CAFe / ICPEdu).
  - Implementação de módulo de geração e custódia segura de chaves em contêineres e enclaves seguros (TEE / HSM).
- **Entregáveis do T1**:
  - Documento de Arquitetura de Software e ADRs do Subsistema de Identidade de Agentes.
  - Pacote de software Go/TypeScript para emissão e resolução de DIDs de agentes integrado ao pipeline da RNP.
  - Relatório Técnico Parcial 1.

### Trimestre 2 (Meses 4 a 6): Protocolo de Delegação com Atenuação Monotônica e Motor OPA/Rego
- **Atividades**:
  - Implementação do validador de invariantes de atenuação monotônica em tempo real (restrição de escopo de ações, tetos de créditos de CPU/GPU e teto de linhas retornadas).
  - Desenvolvimento e publicação de suíte de políticas em Rego (Open Policy Agent) para o controle de admissão em conectores de Data Spaces (Gaia-X / EDC).
  - Implementação do mecanismo de revogação de alta velocidade baseado no padrão StatusList2021.
- **Entregáveis do T2**:
  - Módulo do Gate de Acesso Zero-Trust com latência de avaliação $< 1$ ms e suporte a mais de 10.000 requisições/segundo.
  - Suíte de testes automatizados com simulação de ataques de injeção de privilégio e subdelegação forjada.
  - Artigo submetido ao Simpósio Brasileiro de Segurança da Informação e de Sistemas Computacionais (SBSeg 2027).

### Trimestre 3 (Meses 7 a 9): Trilha de Auditoria Criptográfica Merkle e Integração com Blockchain
- **Atividades**:
  - Implantação da Árvore de Auditoria Merkle append-only (RFC 6962) para registro forense de todas as ações executadas pelos agentes autônomos.
  - Implementação de API REST para solicitação e verificação de Provas Criptográficas de Inclusão $O(\log N)$ para pesquisadores e órgãos de auditoria externa.
  - Piloto de ancoragem periódica do hash raiz de Merkle no Observatório Nacional de Blockchain da RNP (Projeto 3).
- **Entregáveis do T3**:
  - Microsserviço de auditoria e geração de provas criptográficas pronto para ambiente de homologação.
  - Dashboard analítico para visualização de linhagem de autoridade e trilhas de custódia.
  - Relatório Técnico Parcial 2.

### Trimestre 4 (Meses 10 a 12): Homologação em Piloto Real, Testes de Carga e Publicação
- **Atividades**:
  - Condução de testes de estresse em larga escala no backbone da Rede Ipê simulando centenas de agentes orquestrando consultas analíticas simultâneas.
  - Validação da compatibilidade com a camada híbrida de criptografia pós-quântica (ML-KEM / ML-DSA) desenvolvida no Projeto 2.
  - Elaboração da documentação técnica final e repasse de conhecimento para a equipe de operações da RNP.
- **Entregáveis do T4**:
  - Release estável v2.0 da suíte TRUST-ID homologada no ambiente de testes da RNP.
  - Artigo completo submetido ao Simpósio Brasileiro de Redes de Computadores e Sistemas Distribuídos (SBRC 2027).
  - Relatório Final de Conclusão do Plano de Trabalho para o CNPq/RNP.

---

## 4. Guia Estratégico de Respostas para a Entrevista Técnica Remota
*(Preparatório para a banca examinadora do Comitê RNP / SBC — Item 5.2.3 do Edital)*

### Pergunta 1: *"Por que utilizar W3C DID e o método `did:key` em vez de simplesmente emitir tokens JWT convencionais assinados por um servidor OAuth 2.0?"*
> **Resposta Estratégica**:  
> "Tokens JWT tradicionais emitidos por um servidor OAuth 2.0 central introduzem um ponto único de estrangulamento e de falha em arquiteturas federadas multi-institucionais como os Data Spaces da RNP. Em um ambiente com agentes autônomos, subagentes especializados são instanciados e descartados em questão de minutos. O `did:key` é um identificador auto-certificável: a chave pública Ed25519 está codificada diretamente no próprio identificador (`0xed01` multicodec). Isso significa que qualquer nó da federação ou conector de dados pode validar a assinatura de uma requisição em frações de microssegundo, de maneira 100% descentralizada e offline, sem precisar consultar um servidor de chaves remoto ou onerar a infraestrutura central."

### Pergunta 2: *"Como sua arquitetura impede que um agente intermediário conceda a um subagente mais privilégios do que o pesquisador humano originalmente autorizou?"*
> **Resposta Estratégica**:  
> "Através da aplicação formal do **Invariante de Atenuação Monotônica**. Cada nó da cadeia de delegação é criptograficamente encadeado pelo hash SHA-256 do nó pai anterior e assinado com a chave privada do delegador. O portal de Confiança Zero valida matematicamente que o conjunto de ações e dataspaces do filho é um subconjunto estrito do pai ($\mathcal{S}_{k+1} \subseteq \mathcal{S}_k$), que o orçamento de créditos computacionais e o teto de registros retornáveis são menores ou iguais aos do pai, e que a janela temporal de expiração do filho não ultrapassa a do pai. Qualquer tentativa de inflar permissões invalida o encadeamento antes mesmo da consulta ao motor de políticas."

### Pergunta 3: *"Como você estrutura o motor de autorização e qual o papel do Open Policy Agent (OPA/Rego)?"*
> **Resposta Estratégica**:  
> "Utilizamos o padrão arquitetural de desacoplamento do Ponto de Decisão de Política (PDP) e Ponto de Aplicação de Política (PEP). O motor OPA recebe a requisição de acesso contendo o identificador do agente, o recurso solicitado, os atributos de contexto e a cadeia de delegação atenuada. As regras em linguagem Rego verificam a conformidade das credenciais, as cotas de consumo e as políticas da federação. Ao autorizar, o OPA injeta **obrigações mandatórias** (*obligations*), tais como a exigência de commit na Árvore de Auditoria Merkle e o mascaramento compulsório de dados sensíveis para conformidade com a LGPD."

### Pergunta 4: *"Como a Árvore de Merkle garante o não-repúdio e a conformidade com a LGPD sem expor dados confidenciais de outras pesquisas?"*
> **Resposta Estratégica**:  
> "A Árvore de Merkle append-only, implementada sob o padrão RFC 6962, calcula os hashes das folhas com separação de domínio (`0x00`) para impedir colisões de segunda pré-imagem. O hash da raiz pública resume matematicamente todo o histórico de operações. Quando um auditor do CNPq ou da RNP solicita a verificação de uma operação específica, o sistema gera uma **Prova Criptográfica de Inclusão** composta por apenas $O(\log N)$ hashes irmãos. Com essa prova de poucas centenas de bytes, o auditor valida matematicamente que aquela ação pertence à raiz pública, sem que o conteúdo sigiloso das pesquisas concorrentes seja revelado."

### Pergunta 5: *"Qual a sua visão sobre a integração entre a identidade de agentes e as Redes Quanticamente Seguras (Projeto 2)?"*
> **Resposta Estratégica**:  
> "As duas frentes convergem naturalmente. Agentes autônomos operando em links de alta capacidade da Rede Ipê estarão expostos à ameaça de *Harvest Now, Decrypt Later*. Para mitigar isso, projetei no protótipo `pqc-hybrid-kms-mesh` uma camada híbrida: o tráfego e as trocas de chaves combinam o algoritmo clássico X25519 com o padrão em reticulados **NIST FIPS 203 (ML-KEM-768)** via HKDF-SHA256, e a camada de controle SDN utiliza assinaturas híbridas com **NIST FIPS 204 (ML-DSA-65)**. Além disso, a implementação possui clientes para a norma **ETSI GS QKD 014**, permitindo que enlaces providos de equipamentos físicos de criptografia quântica injetem chaves diretamente nos buffers do KMS."

---

## 5. Checklist para a Submissão no JEMS (Até 26/10 às 23h59)

- [x] Link do Currículo Lattes atualizado e salvo.
- [x] Repositórios de código-fonte públicos e auditáveis:
  - `https://github.com/FelipeMadson/trust-id-agentic-authority-delegation` (Release v1.0.0, 21 arquivos, Go 1.22, W3C DID, OPA, Merkle Audit).
  - `https://github.com/FelipeMadson/pqc-hybrid-kms-mesh` (Release v1.0.0, 15 arquivos, NIST FIPS 203/204, ETSI QKD 014).
- [x] Artigos técnicos completos formatados no padrão SBC/RNP:
  - `reports/academic/artigo_trust_id_agentes_inteligentes_rnp.md`
  - `reports/academic/artigo_pqc_redes_quanticamente_seguras_rnp.md`
- [x] Memorial descritivo refinado e focado nas diretrizes dos Projetos 4 e 2.
- [x] Plano de trabalho de 12 meses estruturado por metas trimestrais e entregáveis técnicos.
- [x] Guia de preparação técnica para a entrevista remota com a banca examinadora.
