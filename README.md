# LinhaMestre

Painel em Python/Streamlit para **controle estatístico de qualidade (CEP)** e **gestão de estoque** de uma linha de produção: cadastro de produtos, alertas de estoque e validade, gráficos de controle de Shewhart com regras de Western Electric, tarefas e mensagens internas entre perfis de acesso.

[![CI](https://github.com/codebyjuliamendes/LinhaMestre/actions/workflows/ci.yml/badge.svg)](https://github.com/codebyjuliamendes/LinhaMestre/actions/workflows/ci.yml)
![Python](https://img.shields.io/badge/python-3.11%2B-blue)
![Licença MIT](https://img.shields.io/badge/licen%C3%A7a-MIT-yellow)

## Problema

Em chão de fábrica, os dados de estoque e as medições de qualidade costumam ficar em planilhas separadas. O LinhaMestre junta os dois num só lugar: quem registra a medição de um lote vê na hora se o processo saiu de controle, e quem cuida do estoque vê o que está crítico ou vencendo.

## Funcionalidades

- **Dashboard**: total de produtos, estoque crítico, itens que vencem no prazo configurado, tarefas pendentes do usuário, mensagens não lidas.
- **Produtos**: lista com filtros (categoria, estoque, validade), cadastro, edição, exclusão com confirmação, exportação para Excel e relatórios (por categoria, críticos, validade e Pareto por status de qualidade) com exportação CSV.
- **Controle de qualidade** (Supervisor ou acima):
  - X-barra & R (A2, D3, D4) e X-barra & S (A3, B3, B4), subgrupos de 2 a 10;
  - I-MR (indivíduos e amplitude móvel);
  - as **quatro regras de Western Electric** avaliadas na série inteira, com os pontos destacados no gráfico;
  - histograma das médias e **Cp/Cpk** a partir dos limites de especificação (LIE/LSE) que você informa, com σ estimado por R̄/d2;
  - registro de novas medições a qualquer momento.
- **Tarefas**: minhas tarefas, criação (Supervisor ou acima), visão geral e linha do tempo (Gerente ou acima).
- **Mensagens** internas com resposta direta.
- **Usuários** (Administrador) e **Configurações**: parâmetros persistidos (dias de aviso de validade, mínimo padrão), backup do banco para download e visualização da trilha de auditoria.
- **Perfis hierárquicos**: Operacional < Supervisor < Gerente < CEO < Administrador.
- Tema claro e escuro (segue o navegador; dá para trocar no menu do Streamlit) e layout usável em celular.

## Como rodar

Pré-requisito: [uv](https://docs.astral.sh/uv/) (ele instala o Python certo se precisar).

```bash
uv sync                                    # instala dependências (inclui as de desenvolvimento)
cp .env.example .env                       # opcional; edite as variáveis
export LINHAMESTRE_ADMIN_PASSWORD='troque-esta-senha-1'
uv run linhamestre-seed --with-demo-users  # opcional: dados de demonstração
uv run streamlit run linhamestre_app.py
```

Abra <http://localhost:8501>. Sem `LINHAMESTRE_ADMIN_PASSWORD`, o primeiro boot cria o usuário `admin` com uma senha aleatória, mostrada **uma vez** no log do processo (no terminal ou em `docker logs`). Troque essa senha depois do primeiro acesso.

O seed com `--with-demo-users` cria `ceo`, `gerente`, `supervisor` e `operacional` com a senha de `LINHAMESTRE_DEMO_PASSWORD` (ou com uma senha aleatória exibida no terminal). Os produtos, as medições e os fornecedores do seed são **fictícios**.

## Variáveis de ambiente

| Variável | Padrão | Descrição |
| --- | --- | --- |
| `LINHAMESTRE_DB_PATH` | `linhamestre.db` (`/data/linhamestre.db` no Docker) | Arquivo SQLite |
| `LINHAMESTRE_ADMIN_USERNAME` | `admin` | Usuário do administrador inicial |
| `LINHAMESTRE_ADMIN_PASSWORD` | (gerada) | Senha do administrador inicial; só é usada se o banco não tiver usuários |
| `LINHAMESTRE_TZ` | `America/Sao_Paulo` | Fuso usado para "hoje", prazos e validade |
| `LINHAMESTRE_LOG_LEVEL` | `INFO` | `DEBUG`, `INFO`, `WARNING`, `ERROR` |
| `LINHAMESTRE_LOG_FORMAT` | `json` | `json` (estruturado) ou `text` |
| `LINHAMESTRE_MAX_LOGIN_ATTEMPTS` | `5` | Falhas seguidas antes do bloqueio |
| `LINHAMESTRE_LOCKOUT_MINUTES` | `15` | Duração do bloqueio de login |
| `LINHAMESTRE_DEMO_PASSWORD` | (gerada) | Senha dos usuários de demonstração do seed |

As variáveis são validadas no boot. Com um valor inválido, a aplicação mostra o erro e não sobe.

## Scripts

```bash
uv run pytest                 # testes (unitários + integração da interface)
uv run pytest --cov           # com cobertura
uv run ruff check .           # lint
uv run ruff format .          # formatação
uv run mypy                   # checagem de tipos (strict)
uv run linhamestre-seed -h    # dados de demonstração
```

## Arquitetura

```
linhamestre_app.py        entrada do Streamlit (mantém `streamlit run linhamestre_app.py`)
seed_db.py                entrada compatível para o seed
src/linhamestre/
  config.py               leitura e validação das variáveis de ambiente
  logging_setup.py        logs JSON em stdout
  security.py             PBKDF2, política de senha, bloqueio de login
  domain.py               regras puras: perfis, validação de produto, validade, prazos
  spc.py                  CEP puro: constantes, limites, Western Electric, Cp/Cpk, Pareto
  db.py                   esquema/migrações SQLite e repositório (auditoria na mesma transação)
  seed.py                 dados de demonstração (idempotente)
  app.py                  boot, autenticação, navegação
  ui/                     uma página Streamlit por módulo
tests/                    pytest + streamlit.testing (AppTest)
```

Decisões:

- **A regra fica fora da UI.** `spc.py` e `domain.py` não importam Streamlit nem banco, então os cálculos estatísticos são testados diretamente contra valores de referência.
- **Uma conexão SQLite por execução do script**, em modo WAL e com `busy_timeout`. A versão anterior compartilhava um único cursor global entre todas as sessões e threads.
- **O usuário é recarregado do banco a cada interação.** Mudar o perfil de alguém ou excluir o usuário vale na hora, sem esperar novo login.
- **A auditoria é gravada na mesma transação da alteração** (produtos, usuários, tarefas, mensagens, medições, configurações, login/logout/falhas).
- **O esquema é compatível com bancos da versão 1.0.** As tabelas antigas continuam iguais. No boot, a aplicação só cria `app_settings` e índices, sempre com `IF NOT EXISTS`.

## Segurança

- Senhas com **PBKDF2-HMAC-SHA256** (600 mil iterações) e salt aleatório, comparadas em tempo constante. Hashes legados (SHA-256 simples) continuam funcionando e são convertidos no próximo login.
- Nenhuma senha padrão no código. O administrador inicial vem de variável de ambiente ou de uma senha aleatória.
- Bloqueio temporário após falhas de login consecutivas, com registro na auditoria.
- Conteúdo digitado por usuários é escapado antes de ir para o Markdown, o que impede links, imagens, LaTeX ou HTML injetados.
- As permissões são checadas no servidor em cada página e em cada escrita. Concluir tarefas e marcar mensagens como lidas também confere quem é o dono do registro.
- Proteção XSRF do Streamlit ativa, detalhes de erro ocultos para o usuário final e coleta de estatísticas desativada (`.streamlit/config.toml`).
- O Streamlit não permite definir cabeçalhos HTTP (CSP, HSTS). Em produção, publique atrás de um proxy reverso com HTTPS que adicione esses cabeçalhos.

## Testes

São 76 testes: `spc` (limites e regras contra valores tabelados), `security`, `domain`/`config`, repositório SQLite (CRUD, filtros, permissões por dono, compatibilidade com o banco legado, backup, seed) e integração da interface com `streamlit.testing` (login, bloqueio, menu por perfil, escape de conteúdo, cadastro, mensagens, configurações, sessão derrubada ao excluir o usuário). A cobertura fica em torno de 85%.

## Deploy

### Docker / Compose

```bash
docker compose up --build
```

A imagem é multi-stage (dependências resolvidas pelo `uv.lock`), roda como usuário sem privilégios, tem `HEALTHCHECK` em `/_stcore/health` e guarda o banco no volume `/data`. Para popular com dados de demonstração:

```bash
docker compose exec linhamestre python seed_db.py --with-demo-users
```

### Kubernetes

```bash
kubectl create secret generic linhamestre-secrets --from-literal=admin-password='troque-esta-senha-1'
kubectl apply -f k8s/
```

O manifesto cria um `PersistentVolumeClaim` e usa **uma réplica** com estratégia `Recreate`, porque o SQLite é um arquivo local. O Service é `NodePort` na porta `30851`.

### CI

O GitHub Actions roda lint, formatação, mypy e testes. Depois constrói a imagem Docker e faz um smoke test (health check, usuário não-root, seed). O Dependabot acompanha as dependências `uv`, as Actions e a imagem base.

## Limitações

- SQLite, uma instância só. Para várias réplicas seria preciso migrar para um banco em rede.
- O bloqueio de login fica em memória do processo e é zerado quando a aplicação reinicia.
- O I-MR usa as médias registradas de cada subgrupo como valores individuais, porque o sistema não guarda medições unitárias.
- Os gráficos de Shewhart exigem o mesmo tamanho de amostra em todos os subgrupos de um produto. Se os tamanhos variarem, a tela avisa e não calcula os limites.
- Não há envio de e-mail nem notificações externas.
- O backup gera um download. Para restaurar, pare a aplicação e substitua o arquivo do banco.

## Licença

[MIT](LICENSE) © Júlia Mendes
