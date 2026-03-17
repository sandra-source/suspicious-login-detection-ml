# Sistema de Mapeamento de Perfil Comportamental para Detecção de Logins Anômalos

> Pesquisa aplicada em segurança da informação com Machine Learning — iniciativa independente com embasamento científico.  
> Artigo técnico em desenvolvimento para submissão ao **MCTI (Ministério da Ciência, Tecnologia e Inovações)**.

---

## Visão Geral

Este projeto implementa um sistema de **detecção de anomalias em eventos de login** baseado em modelagem comportamental de usuários. Em vez de utilizar regras fixas ou listas de bloqueio, o sistema aprende o padrão individual de cada usuário — quais máquinas utiliza, em quais horários e dias da semana — e gera um **score de risco calibrado** para cada novo evento de acesso.

A abordagem é fundamentada em pesquisas científicas na área de **User and Entity Behavior Analytics (UEBA)** e combina:

- **Machine Learning supervisionado** com LightGBM calibrado isotonicamente
- **Modelagem probabilística comportamental** sem suavização de Laplace
- **Janela horária principal por usuário** (*core window*) como feature estrutural
- **Regras de negócio híbridas** combinando estatística e heurísticas de segurança
- **Baseline dinâmico de p95** para análise de volume com estado persistido em SQLite
- **API REST em Flask** com autenticação via token AES-CBC para integração com sistemas externos

O projeto foi concebido, arquitetado e implementado de forma independente, como iniciativa própria dentro do ambiente corporativo, superando em completude e aderência ao negócio uma proposta de fornecedor externo de grande porte para o mesmo problema.

---

## Motivação e Contexto Científico

Sistemas tradicionais de segurança baseados em regras estáticas apresentam limitações conhecidas: alta taxa de falsos positivos, incapacidade de adaptar-se ao comportamento individual e ausência de contextualização temporal. A literatura em UEBA (Tuor et al., 2017; Buczak & Guven, 2016) aponta que a modelagem probabilística do comportamento histórico do usuário supera abordagens baseadas em assinaturas em cenários de detecção de ameaças internas (*insider threats*) e acessos comprometidos.

Este sistema adota essa premissa e a operacionaliza em um pipeline de produção completo, desde a pré-computação offline até a inferência em tempo real via API.

### Hipótese Central

> *O comportamento de acesso de um usuário legítimo é estatisticamente estável ao longo do tempo. Desvios significativos em relação ao perfil histórico — combinando máquina, horário e dia da semana — são preditores confiáveis de eventos anômalos.*

---

## Arquitetura do Sistema

```
┌─────────────────────────────────────────────────────────────┐
│                    PIPELINE OFFLINE                         │
│                                                             │
│  SecurityEventLoggers.csv                                   │
│          │                                                  │
│          ▼                                                  │
│  precompute_profiles.py                                     │
│  ├── Probabilidades por máquina  P(m|u)                    │
│  ├── Probabilidades por hora     P(h|u)                    │
│  ├── Probabilidades por dia      P(d|u)                    │
│  ├── Core Window por usuário     (janela horária principal) │
│  ├── Backfill diário             (daily_user_machines)      │
│  └── api_cache.db  (DuckDB — read-only, thread-safe)       │
│                                                             │
│  train_model.py                                             │
│  ├── Split temporal 80/20 (sem data leakage)               │
│  ├── Feature engineering (5 features)                      │
│  ├── LightGBM + Calibração Isotônica (CV=5)                │
│  ├── Avaliação: ROC-AUC, AP, Curva PR, Matriz de Confusão  │
│  └── modelo_lightgbm.joblib + modelo_lightgbm.json         │
└─────────────────────────────────────────────────────────────┘
                          │
                          ▼
┌─────────────────────────────────────────────────────────────┐
│                    PIPELINE ONLINE (API)                    │
│                                                             │
│  POST /analisar                                             │
│  ├── Auth: Bearer Token (AES-CBC)                          │
│  ├── Consulta DuckDB read-only (thread-safe)               │
│  ├── Extração de features em tempo real                     │
│  ├── Janela deslizante 10h (SQLite compartilhado)          │
│  ├── Baseline p95 dinâmico por usuário                     │
│  ├── Inferência: LightGBM calibrado                        │
│  └── Relatório JSON com score, DNA e justificativas        │
└─────────────────────────────────────────────────────────────┘
```

---

## Análise Técnica do Sistema

### 1. Base Analítica com DuckDB

O sistema utiliza **DuckDB** para realizar o processamento pesado de agregação e cálculo de probabilidades sobre o histórico completo de logs. Esta escolha foi deliberada por três razões principais:

- **Velocidade:** DuckDB é projetado para consultas analíticas (OLAP) com `GROUP BY` e agregações sobre milhões de registros, processando os dados em microsegundos com uso de vetorização nativa.
- **Eficiência de memória:** Os dados são processados diretamente do CSV sem necessidade de carregá-los integralmente em memória Python/Pandas, tornando o sistema escalável para grandes volumes de logs.
- **Expressividade:** A lógica complexa de junção e agregação é expressa de forma declarativa em SQL, mantendo o código auditável e de fácil manutenção.

Em produção, o banco `api_cache.db` é aberto em modo *read-only* por requisição, garantindo segurança com múltiplos workers concorrentes.

### 2. Engenharia de Features Probabilísticas: o "DNA" do Usuário

O coração do modelo não são os dados brutos de login, mas sim as **probabilidades comportamentais** derivadas do histórico individual de cada usuário. As features `login_machine_prob`, `login_hour_prob` e `login_day_prob` constroem um perfil único — um DNA comportamental — que representa o padrão de acesso legítimo daquele usuário específico.

Um login que se desvia significativamente desse DNA é, por definição, anômalo. Esta abordagem é análoga às técnicas de *behavioral fingerprinting* descritas na literatura de UEBA.

**Decisão crítica de design:** As probabilidades foram calculadas **sem suavização de Laplace**. Isso preserva a discriminabilidade do modelo: uma máquina nunca antes acessada pelo usuário recebe `machine_prob = 0`, o que é semanticamente correto — o modelo deve ser maximamente sensível a máquinas inéditas.

### 3. Engenharia de Features Baseada em Regras de Negócio

O sistema não confia exclusivamente na estatística. Regras de negócio críticas foram incorporadas como features para capturar anomalias lógicas que a probabilidade histórica sozinha não detectaria:

- **`is_access_control_user`:** Reconhece que usuários com perfil de AccessControl (alto volume de acessos a múltiplas máquinas) possuem comportamento estruturalmente diferente e devem ser avaliados com limiares distintos. Isso evita falsos positivos sistemáticos para um segmento legítimo de usuários.
- **Verificação de correspondência de código (code mismatch):** A regra de que o identificador numérico do usuário deve corresponder ao da máquina acessada é uma heurística de segurança fortíssima. Uma violação dessa correspondência em usuários sem perfil de AccessControl é um sinal de alerta quase inequívoco de acesso indevido.

Esta combinação de estatística e regras de negócio é o que caracteriza o sistema como **híbrido** — e o que o diferencia de abordagens puramente baseadas em ML ou puramente baseadas em regras.

### 4. Modelo de Machine Learning: LightGBM Calibrado

O modelo utiliza **LightGBM** com calibração isotônica para aprender os padrões complexos de interação entre as features. As escolhas de design incluem:

- **`scale_pos_weight=10`:** Em problemas de segurança e detecção de fraude, eventos maliciosos são ordens de magnitude mais raros que eventos normais. O peso assimétrico garante que o modelo não ignore a classe minoritária.
- **Calibração isotônica (CV=5):** A calibração transforma os scores brutos do modelo em probabilidades interpretáveis como risco real. Um score de 70% deve significar que, historicamente, 70% dos eventos com esse score eram de fato anômalos.
- **Modelo final com 100% dos rótulos:** Após a avaliação rigorosa com split temporal, o modelo final é retreinado sobre todos os dados rotulados disponíveis, maximizando a informação utilizada em produção.

### 5. Arquitetura *On-Demand* e Janela Deslizante

A decisão de não pré-carregar perfis de todos os usuários na inicialização — consultando o DuckDB dinamicamente por requisição — é um padrão de design de software deliberado. O sistema inicia instantaneamente e consome memória proporcional à atividade real, não ao tamanho total do histórico.

O estado de curto prazo (janela de 10 horas e baseline diário) é mantido em **SQLite compartilhado entre workers**, com operações atômicas que garantem consistência sem locks explícitos. Isso permite que a análise de volume em tempo real enriqueça o contexto de cada evento sem degradar a latência da API.

---

## Features do Modelo

| Feature | Descrição | Tipo |
|---|---|---|
| `login_machine_prob` | P(máquina \| usuário) — probabilidade histórica de acesso a esta máquina | Float [0,1] |
| `is_access_control_user` | Flag: usuário opera com AccessControlId válido (perfil de alto volume) | Binário |
| `is_in_hour_core` | Flag: horário do evento está dentro da janela horária principal do usuário | Binário |
| `dist_to_hour_core` | Distância circular (horas) até a janela principal — 0 se dentro | Float [0,12] |
| `hour_core_width` | Largura da janela horária principal (horas que cobrem 85% dos acessos) | Float [1,24] |

---

## Janela Horária Principal (*Core Window*)

Uma contribuição central deste sistema é o cálculo da **menor janela horária contígua** que cobre 85% dos acessos históricos de cada usuário, usando um algoritmo de janela deslizante circular:

```
Dado: contagens horárias C[0..23]
Meta: encontrar a menor janela contígua (circular) que cubra ≥ 85% do total

Algoritmo: sliding window de dois ponteiros em C || C (vetor duplicado)
Complexidade: O(24) por usuário
```

Essa abordagem captura padrões não-uniformes — usuários em turnos noturnos, horários que cruzam a meia-noite — sem suposições sobre a distribuição dos acessos.

---

## Pipeline de Treinamento

### Etapa 1 — Pré-computação Offline (`precompute_profiles.py`)

Processa o histórico completo de eventos e gera os artefatos necessários para inferência instantânea:

- `machine_probs.parquet` — P(máquina | usuário)
- `hour_probs.parquet` — P(hora | usuário), sem Laplace
- `day_probs.parquet` — P(dia_semana | usuário), sem Laplace
- `hour_core_window.parquet` — janela horária principal por usuário
- `daily_user_machines.parquet` — backfill para baseline p95 dinâmico
- `api_cache.db` — banco DuckDB com índices para consulta em < 5ms

### Etapa 2 — Treinamento (`train_model.py`)

1. **Carregamento e merge** dos logs com alertas classificados por analistas humanos (status 3 = falso positivo; status 4 = alerta verdadeiro)
2. **Split temporal 80/20** com ajuste automático para garantir representação da classe positiva em treino e teste — sem data leakage
3. **Feature engineering sem leakage:** probabilidades recalculadas exclusivamente sobre dados anteriores ao ponto de corte
4. **Treinamento** do modelo LightGBM base com `scale_pos_weight=10`
5. **Calibração** isotônica em conjunto de validação temporal
6. **Avaliação** com ROC-AUC, Average Precision, Curva Precision-Recall e Matriz de Confusão
7. **Modelo final** retreinado com 100% dos rótulos e calibração CV=5

### Métricas e Relatórios Gerados

```
files/reports/
├── roc_curve.png
├── precision_recall_curve.png
├── score_histogram.png
├── calibration_curve.png
├── confusion_matrix.png
└── metrics.json
```

---

## API REST

### Autenticação

Todos os endpoints protegidos requerem token Bearer criptografado com AES-CBC:

```
Authorization: Bearer <token_criptografado_base64>
```

### `POST /analisar`

Analisa um evento de login e retorna score de risco, DNA comportamental e justificativas.

**Requisição:**
```json
{
  "user": "12345",
  "machineName": "CLI-12345-WORKSTATION",
  "generatedAt": "2025-03-16T09:30:00",
  "accessControlId": "AC-789"
}
```

**Resposta:**
```json
{
  "classe": "normal",
  "score_risco_final": "23%",
  "analise_evento_atual": {
    "usuario": "12345",
    "maquina": "CLI-12345-WORKSTATION",
    "data_login": "2025-03-16 09:30:00",
    "probabilidade_maquina": "34.2%",
    "probabilidade_hora": "18.7%",
    "probabilidade_dia": "22.1%",
    "janela_horaria_principal": "08–17h"
  },
  "justificativa_risco": [
    "Janela horária principal do usuário: 08–17h.",
    "Limiar diário dinâmico (máquinas): 6.",
    "Hoje: 2 máquinas distintas.",
    "Janela 10h: 1 máquinas / 3 eventos."
  ],
  "dna_comportamental_usuario": {
    "maquinas": {
      "CLI-12345-WORKSTATION": "34.2%",
      "CLI-12345-NOTEBOOK": "28.1%"
    },
    "horas": { "9": "18.7%", "10": "15.3%" },
    "dias": { "Segunda": "22.1%", "Terça": "19.4%" }
  }
}
```

### `GET /health`

Verifica o status da API e do detector.

---

## Estrutura do Projeto

```
.
├── api/
│   └── suspicious_login_api.py      # Flask app factory, autenticação, rota /analisar
├── suspicious_login/
│   └── detector_logic.py            # Lógica principal: features, inferência, relatório
├── files/
│   ├── SecurityEventLoggers.csv     # Logs de eventos de login
│   ├── Alerts.csv                   # Alertas classificados por analistas
│   ├── precomputed/                 # Artefatos gerados pelo precompute
│   │   ├── api_cache.db
│   │   ├── machine_probs.parquet
│   │   ├── hour_probs.parquet
│   │   ├── day_probs.parquet
│   │   ├── hour_core_window.parquet
│   │   └── daily_user_machines.parquet
│   └── reports/                     # Métricas e visualizações do treinamento
├── precompute_profiles.py           # Etapa 1: pré-computação offline
├── train_model.py                   # Etapa 2: treinamento e avaliação
├── modelo_lightgbm.joblib           # Modelo treinado (artefato de produção)
├── modelo_lightgbm.json             # Metadados: features, cutoff, notas
├── wsgy.py                          # Entry point WSGI
└── .env                             # SECRET_KEY, TOKEN (não versionado)
```

---

## Instalação e Execução

### Dependências

```bash
pip install flask python-dotenv pycryptodome duckdb lightgbm \
            scikit-learn pandas numpy joblib matplotlib
```

### Configuração

```bash
# .env
SECRET_KEY=sua_chave_aes_32_bytes
TOKEN=seu_token_esperado
```

### Pré-computação (executar uma vez ou ao atualizar os dados)

```bash
python precompute_profiles.py
```

### Treinamento

```bash
python train_model.py
```

### Execução da API

```bash
# Desenvolvimento
python wsgy.py

# Produção (múltiplos workers gthread)
gunicorn wsgy:app --workers 4 --worker-class gthread --threads 4
```

---

## Considerações Técnicas

**Thread safety:** A API abre conexões DuckDB *read-only* por requisição, garantindo isolamento entre workers concorrentes. O estado da janela deslizante é persistido em SQLite com operações atômicas.

**Latência:** O pipeline de inferência é otimizado para resposta em tempo real. A consulta ao DuckDB retorna em < 5ms; a inferência do modelo em < 2ms. O processamento pesado é integralmente realizado na fase offline.

**Escalabilidade:** A separação entre pré-computação offline e inferência online permite escalar a API horizontalmente sem reprocessar o histórico de dados.

---

## Desafios Tecnológicos e Evolução do Sistema

### Primeira versão: barreiras de escalabilidade

Durante a fase inicial do projeto, o sistema enfrentou limitações críticas de performance que inviabilizaram a implantação em produção:

- **Complexidade algorítmica elevada:** O algoritmo original operava com complexidade $O(n^{\log n})$, resultando em um tempo de treinamento de aproximadamente **40 minutos em ambiente local**.
- **Estouro de memória em servidor:** Ao tentar a implantação, o modelo apresentou *memory overflow*. Instâncias com 4GB, 8GB e até 16GB de RAM foram testadas sem sucesso — o sistema simplesmente não era viável em produção nessa arquitetura.

Esses gargalos exigiram uma **refatoração profunda**, realizada em duas etapas:

### Etapa 1 — Otimização para tempo constante $O(1)$

A lógica de análise foi redesenhada para que o tempo de inferência **não crescesse com o volume do histórico**. A chave foi a separação entre pré-computação offline (probabilidades, core window, índices DuckDB) e inferência online (consulta instantânea aos artefatos pré-computados).

Com essa mudança, o tempo de análise de um evento de login tornou-se **independente do tamanho do banco de dados** — o mesmo comportamento para 10 mil ou 10 milhões de registros. O tempo de análise estabilizou-se entre **30ms e 50ms** por evento.

### Etapa 2 — Migração para LightGBM

Para atingir a performance necessária em tempo real, o algoritmo de Machine Learning foi migrado para **LightGBM**. O resultado foi uma redução drástica no tempo de inferência:

| Versão | Tempo de inferência por login |
|---|---|
| Modelo inicial | ~30–50 segundos |
| LightGBM (versão final) | **2ms – 4ms** |

Essa evolução representa uma redução de mais de **99,9% no tempo de resposta**, viabilizando o uso em produção em ambientes de alto volume de eventos.

---

## Contexto de Pesquisa

Este sistema foi desenvolvido com embasamento em revisão de literatura técnica e acadêmica nas seguintes áreas:

- **UEBA (User and Entity Behavior Analytics):** modelagem probabilística de comportamento para detecção de anomalias em acessos
- **Anomaly Detection em Logs de Acesso:** métodos de detecção baseados em desvios do perfil histórico individual
- **Calibração de Classificadores:** técnicas de calibração isotônica para interpretabilidade de scores de risco em contextos de segurança
- **Gradient Boosting para dados tabulares:** LightGBM como estado da arte para classificação com features de baixa dimensionalidade e alto desbalanceamento de classes

### Referências utilizadas no desenvolvimento

A pesquisa bibliográfica foi orientada por estudos sobre o desempenho de algoritmos de classificação em detecção de anomalias em segurança, com foco em:

- **Random Forest para detecção de anomalias em redes:** estudos como *"Performance Analysis of Random Forest Algorithm for Network Anomaly Detection using Feature Selection"* foram referência central para a estratégia de seleção de features (*feature selection*), orientando a decisão de não utilizar a totalidade do dataset no treinamento — priorizando precisão e performance sobre volume de dados.
- **Hist Gradient Boosting (HGB):** materiais sobre HGB foram consultados durante a fase de avaliação de algoritmos, compondo o embasamento para a escolha final do LightGBM como modelo de produção.

Essa fundamentação científica foi determinante para as decisões de arquitetura do modelo e é parte central do artigo técnico-científico atualmente em desenvolvimento para submissão ao **MCTI**, proposto pelos próprios avaliadores a partir dos resultados e da metodologia aplicada neste projeto.

---

## Sobre

Desenvolvido por **Sandra Carvalho** — Machine Learning Engineer | Researcher | Full Stack Developer  
[linkedin.com/in/sandra-carvalho-3b6797196](https://www.linkedin.com/in/sandra-carvalho-3b6797196)

> *Projeto desenvolvido por iniciativa própria, com embasamento em pesquisas científicas aplicadas.*

---

*Código-fonte proprietário — repositório público apenas para fins de documentação e portfólio técnico.*
