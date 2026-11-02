# API EduConnect (Node.js + Express + MariaDB)

```
GitHub Pages (HTML/JS)  ──fetch + JWT──▶  Render (esta API)  ──mysql2──▶  AlwaysData (MariaDB)
```

## Arquivos

| Arquivo | Função |
|---|---|
| `server.js` | A API inteira (cada linha comentada) |
| `package.json` | Dependências e comando de início (`npm start`) |
| `.env.example` | Modelo das variáveis de ambiente |
| `seed-senhas.js` | Grava hashes bcrypt reais nos 2 usuários de demonstração (uso único) |
| `frontend/api.js` | Cliente JS para colocar em `pages/` no repositório do site |

---

## 1. Banco no AlwaysData

1. Painel AlwaysData → **Bancos de dados → MySQL/MariaDB → Adicionar um banco**. O nome ganha o prefixo da conta (ex.: `minhaconta_educonnect`).
2. Crie também um **usuário do banco** (ex.: `minhaconta_api`) com acesso a esse banco.
3. Abra o **phpMyAdmin**, selecione o banco e importe `educonnect.sql`, **depois de apagar as linhas `CREATE DATABASE ...` e `USE educonnect;`** do início do arquivo (no AlwaysData você não escolhe o nome do banco por SQL).
4. Anote: host (`mysql-SUACONTA.alwaysdata.net`), usuário, senha e nome do banco.

> **Senhas de demonstração:** os hashes do `educonnect.sql` são ilustrativos e **não** correspondem a `123456`/`prof123`; o login falharia. Rode uma vez, no seu computador:
> ```bash
> cp .env.example .env     # preencha DB_*
> npm install
> npm run seed-senhas
> ```
> Se der timeout ao conectar de casa, confira no painel do AlwaysData se o acesso externo ao banco está permitido.

## 2. Testar localmente (opcional)

```bash
npm install
npm start                   # http://localhost:3000/health  →  {"ok":true,"banco":true}
```

## 3. Publicar no Render

1. Crie um repositório no GitHub só com esta pasta (`server.js`, `package.json`, `package-lock.json`, `.env.example`, `.gitignore`). **Nunca suba o `.env`.**
2. Render → **New → Web Service** → conecte o repositório.
3. Configure:
   - **Runtime:** Node · **Build Command:** `npm install` · **Start Command:** `npm start`
   - **Health Check Path:** `/health`
4. Em **Environment**, cadastre as variáveis do `.env.example`. As obrigatórias: `DB_HOST`, `DB_PORT`, `DB_USER`, `DB_PASSWORD`, `DB_NAME`, `JWT_SECRET` (≥ 32 caracteres), `CORS_ORIGINS`.
5. `CORS_ORIGINS` deve ser **só o domínio**, sem caminho e sem barra final: `https://seuusuario.github.io` (e **não** `https://seuusuario.github.io/educonnect/`).
6. Depois do deploy, abra `https://SEU-SERVICO.onrender.com/health`.

### Limitações do plano gratuito do Render
- O serviço **hiberna após 15 min sem uso**; a primeira requisição depois disso pode levar cerca de 1 minuto.
- **SMTP (portas 25/465/587) é bloqueado** nos serviços gratuitos. Por isso o e-mail de recuperação de senha usa a **API HTTPS da Brevo** (`BREVO_API_KEY` + `EMAIL_REMETENTE`, com o remetente verificado na Brevo). Sem essas variáveis, o e-mail só é simulado no log (fora de produção).

## 4. Ligar o frontend (GitHub Pages)

1. Copie `frontend/api.js` para `pages/api.js` e troque `API_URL` pelo endereço do Render.
2. Em cada página, inclua `<script src="api.js"></script>` antes do script principal.
3. Troque os dados de demonstração pelas chamadas abaixo. O token fica em `sessionStorage["token"]`.

| Página | O que substituir | Chamada |
|---|---|---|
| `login.html` | `usuarioDemo` e a comparação | `const r = await EduAPI.loginAluno(email.value, senha.value); sessionStorage.setItem("token", r.token); sessionStorage.setItem("usuarioLogado", JSON.stringify(r.usuario));` (erro → mostrar `e.message`) |
| `loginProf.html` | idem (hoje é cópia do login do aluno e redireciona para `perfil.html`) | `EduAPI.loginProfessor(...)`, gravar `r.professor` em `"professorLogado"` e ir para **`painel-professor.html`** |
| `esqueci-senha.html` | comentário "O envio real deve ser integrado" | `await EduAPI.esqueciSenha(email.value, cpf.value)` |
| `perfil.html` / `desempenho.html` | constantes `DADOS`, `notasBim`, `DOCUMENTOS` | `const r = await EduAPI.desempenho();` → `DADOS = r.dados`, `DOCUMENTOS = r.documentos`, `r.bimestres[ano][disciplina]` = `[nota1, nota2, nota3]`; foto: `EduAPI.perfil()` e `EduAPI.salvarFoto(dataUrl)` |
| `painel-professor.html` | `banco` do `localStorage` | `alunos()`, `lancamentos(id, ano)`, `salvarLancamentos(id, ano, {bim, notas, faltas, documentos})`, `novoAluno`, `editarAluno`, `excluirAluno`, `anos`, `novoAno` |
| `secretaria.html` | protocolo `DEMO-...` gerado no navegador | `const r = await EduAPI.solicitar({nome, email, matricula, documento, detalhes}); r.protocolo` |

Os formatos de resposta seguem os que as páginas já usam (`null` = não lançado; meses `Fev…Dez`).

## 5. Rotas

| Método | Rota | Acesso |
|---|---|---|
| GET | `/health` | público |
| POST | `/api/auth/login/aluno` · `/api/auth/login/professor` | público |
| POST | `/api/auth/esqueci-senha` · `/api/auth/redefinir-senha` | público |
| GET | `/api/aluno/perfil` · `/api/aluno/desempenho` | aluno |
| PUT | `/api/aluno/foto` | aluno |
| GET/POST | `/api/professor/anos` | professor |
| GET/POST | `/api/professor/alunos` | professor |
| PUT/DELETE | `/api/professor/alunos/:id` | professor |
| GET/PUT | `/api/professor/alunos/:id/lancamentos/:ano` | professor |
| POST | `/api/secretaria/solicitacoes` | público (limitado a 10/hora por IP) |
| GET | `/api/secretaria/solicitacoes/:protocolo` | público (retorna só status) |

## 6. Pontos de atenção

- **Link de recuperação:** o e-mail aponta para `FRONTEND_URL/pages/redefinir-senha.html?token=...`. Essa página ainda não existe; ela precisa de um campo de nova senha chamando `EduAPI.redefinirSenha(token, novaSenha)`.
- **CPF:** a recuperação exige o CPF cadastrado. As contas do SQL têm `cpf NULL` e o modal "Novo aluno" não tem campo de CPF (a API aceita `cpf` opcional em `POST/PUT /alunos`).
- **Senha de novo aluno:** se o professor não enviar `senha`, a API gera uma provisória e a devolve **uma única vez** em `senhaProvisoria`.
- **Ano sem dados:** o SQL só traz 2026 para a Maria (o front de demonstração tinha 2025 também). A API devolve apenas anos com lançamentos; `desempenho.html`/`perfil.html` calculam frequência dividindo por aulas e mostram `NaN` em um ano totalmente vazio.
- **Segurança:** consultas parametrizadas, senhas com bcrypt, JWT de 8 h, CORS restrito, `helmet` e limite de tentativas. Os tokens vão no cabeçalho `Authorization` (e não em cookies) porque cookies entre `github.io` e `onrender.com` são bloqueados como "terceiros".
- Não consegui rodar a API contra um MariaDB real neste ambiente; a sintaxe foi verificada, mas faça o teste de ponta a ponta após o deploy.
