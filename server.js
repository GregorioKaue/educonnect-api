// API do EduConnect (Express + MySQL). Rotas espelham o objeto EduAPI de pages/api.js.
require("dotenv").config();
const crypto = require("crypto");
const express = require("express");
const cors = require("cors");
const helmet = require("helmet");
const rateLimit = require("express-rate-limit");
const mysql = require("mysql2/promise");
const bcrypt = require("bcryptjs");
const jwt = require("jsonwebtoken");
const nodemailer = require("nodemailer");

const { JWT_SECRET, SMTP_HOST } = process.env; // CODIGO_ESCOLA foi removido: o cadastro de professor não exige mais esse código
const FRONTEND_URL = (process.env.FRONTEND_URL || "http://localhost:5500").replace(/\/$/, "");
const PROD = process.env.NODE_ENV === "production";
if (!JWT_SECRET || JWT_SECRET.length < 32) {
  console.error("Defina JWT_SECRET com pelo menos 32 caracteres (veja .env.example).");
  process.exit(1);
}

// ---------- Banco ----------
const pool = mysql.createPool({
  host: process.env.DB_HOST, port: Number(process.env.DB_PORT) || 3306,
  user: process.env.DB_USER, password: process.env.DB_PASSWORD, database: process.env.DB_NAME,
  waitForConnections: true, connectionLimit: 5, charset: "utf8mb4",
  dateStrings: true // DATE volta como "2026-02-03", como o frontend espera
});

async function transacao(fn) {
  const c = await pool.getConnection();
  try { await c.beginTransaction(); const r = await fn(c); await c.commit(); return r; }
  catch (e) { await c.rollback(); throw e; }
  finally { c.release(); }
}

// ---------- Utilitários ----------
class Erro extends Error { constructor(status, msg) { super(msg); this.status = status; } }
const wrap = fn => (req, res, next) => fn(req, res, next).catch(next);
const txt = (v, max) => (typeof v === "string" ? v.trim().slice(0, max) : "");
const digitos = v => String(v ?? "").replace(/\D/g, "");
const emailOk = e => e.length <= 150 && /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(e);
const senhaOk = s => typeof s === "string" && s.length >= 8 && s.length <= 72; // 72 = limite do bcrypt
const hashSenha = s => bcrypt.hash(s, 10);
const HASH_FALSO = bcrypt.hashSync("senha-falsa", 10); // Gasta o mesmo tempo quando o e-mail não existe

const MESES = ["Fev", "Mar", "Abr", "Mai", "Jun", "Ago", "Set", "Out", "Nov", "Dez"];
const SITUACOES = ["entregue", "analise", "pendente"];
const DOCS_ALUNO = ["Certidão de nascimento", "RG ou CPF do aluno", "Comprovante de residência",
  "Histórico escolar anterior", "Cartão de vacina", "Foto 3x4", "Declaração de transferência",
  "Termo de autorização de imagem"];
const DOCS_SECRETARIA = ["Declaração de matrícula", "Histórico escolar", "Atestado de frequência", "Outro assunto"];

function cpfOk(valor) {
  const n = digitos(valor);
  if (n.length !== 11 || /^(\d)\1{10}$/.test(n)) return false;
  for (let t = 9; t < 11; t++) {
    let soma = 0;
    for (let i = 0; i < t; i++) soma += n[i] * (t + 1 - i);
    if (((soma * 10) % 11) % 10 !== Number(n[t])) return false;
  }
  return true;
}

// Valida nome e e-mail. O CPF é OPCIONAL: vazio vira null; se for enviado, precisa ser válido.
function pessoa(b) {
  const nome = txt(b.nome, 120), email = txt(b.email, 150).toLowerCase(), cpf = digitos(b.cpf);
  if (nome.length < 3) throw new Erro(400, "Informe o nome completo.");
  if (!emailOk(email)) throw new Erro(400, "Informe um e-mail válido.");
  if (cpf && !cpfOk(cpf)) throw new Erro(400, "O CPF informado é inválido.");
  return { nome, email, cpf: cpf || null };
}

const ALFABETO = "ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz23456789"; // sem caracteres ambíguos
const senhaAleatoria = () => Array.from({ length: 10 }, () => ALFABETO[crypto.randomInt(ALFABETO.length)]).join("");

async function gerarMatricula() {
  for (let i = 0; i < 10; i++) {
    const m = new Date().getFullYear() + String(crypto.randomInt(0, 1e6)).padStart(6, "0");
    const [r] = await pool.query("SELECT 1 FROM alunos WHERE matricula = ?", [m]);
    if (!r.length) return m;
  }
  throw new Erro(500, "Não foi possível gerar a matrícula. Tente de novo.");
}

async function criarAluno({ nome, email, cpf, turma, matricula, senha }) {
  const hash = await hashSenha(senha);
  return transacao(async c => {
    const [r] = await c.query(
      "INSERT INTO alunos (nome, email, cpf, matricula, turma, senha_hash) VALUES (?,?,?,?,?,?)",
      [nome, email, cpf, matricula, turma, hash]);
    await c.query("INSERT INTO documentos (aluno_id, nome) VALUES ?", [DOCS_ALUNO.map(n => [r.insertId, n])]);
    return r.insertId;
  });
}

const discs = async () => (await pool.query("SELECT id, nome, aulas_por_mes FROM disciplinas ORDER BY ordem, id"))[0];

// Transforma linhas {disciplina_id, idx, valor} em { disciplina: [n posições, null = sem lançamento] }.
function matriz(ds, linhas, n) {
  const nomes = Object.fromEntries(ds.map(d => [d.id, d.nome]));
  const o = Object.fromEntries(ds.map(d => [d.nome, Array(n).fill(null)]));
  linhas.forEach(l => { if (nomes[l.disciplina_id]) o[nomes[l.disciplina_id]][l.idx] = Number(l.valor); });
  return o;
}

// ---------- Autenticação ----------
const assinar = (tipo, id) => jwt.sign({ id, tipo }, JWT_SECRET, { expiresIn: "8h" });
const exigir = tipo => (req, res, next) => {
  const h = req.headers.authorization || "";
  let p;
  try { p = jwt.verify(h.startsWith("Bearer ") ? h.slice(7) : "", JWT_SECRET); }
  catch { return res.status(401).json({ erro: "Sessão expirada. Entre novamente." }); }
  if (p.tipo !== tipo) return res.status(403).json({ erro: "Acesso não permitido." });
  req.usuario = p;
  next();
};

async function autenticar(tabela, email, senha) { // tabela vem sempre de constante, nunca do cliente
  const [[u]] = await pool.query(`SELECT * FROM ${tabela} WHERE email = ?`, [txt(email, 150).toLowerCase()]);
  const ok = await bcrypt.compare(typeof senha === "string" ? senha : "", u ? u.senha_hash : HASH_FALSO);
  if (!u || !ok) throw new Erro(401, "E-mail ou senha incorretos.");
  return u;
}

// ---------- E-mail ----------
const transporte = SMTP_HOST ? nodemailer.createTransport({
  host: SMTP_HOST, port: Number(process.env.SMTP_PORT) || 587,
  auth: process.env.SMTP_USER ? { user: process.env.SMTP_USER, pass: process.env.SMTP_PASS } : undefined
}) : null;

async function enviarRecuperacao(email) { // Recuperação só pelo e-mail (o CPF não é mais obrigatório)
  for (const [tipo, tabela] of [["aluno", "alunos"], ["professor", "professores"]]) {
    const [[u]] = await pool.query(`SELECT id, nome FROM ${tabela} WHERE email = ?`, [email]);
    if (!u) continue;
    const token = crypto.randomBytes(32).toString("hex"); // 64 caracteres hex, como o redefinir-senha.html exige
    const hash = crypto.createHash("sha256").update(token).digest("hex");
    await pool.query("INSERT INTO redefinicoes_senha (tipo, usuario_id, token_hash, expira_em) VALUES (?,?,?, DATE_ADD(UTC_TIMESTAMP(), INTERVAL 1 HOUR))",
      [tipo, u.id, hash]);
    const link = `${FRONTEND_URL}/pages/redefinir-senha.html?token=${token}`;
    if (!transporte) { if (!PROD) console.log("[DEV] Link de recuperação:", link); continue; }
    await transporte.sendMail({
      from: process.env.SMTP_FROM || process.env.SMTP_USER, to: email,
      subject: "EduConnect: redefinição de senha",
      text: `Olá, ${u.nome}.\n\nPara criar uma nova senha, acesse (válido por 1 hora):\n${link}\n\nSe não foi você, ignore este e-mail.`
    });
  }
}

// ---------- App ----------
const app = express();
app.set("trust proxy", 1); // Render fica atrás de proxy: necessário para o limitador enxergar o IP real
app.use(helmet());
const origens = (process.env.CORS_ORIGINS || "").split(",").map(s => s.trim().replace(/\/$/, "")).filter(Boolean);
app.use(cors({
  origin: (origin, cb) => cb(null, !origin || origens.includes(origin) ||
    (!PROD && /^https?:\/\/(localhost|127\.0\.0\.1)(:\d+)?$/.test(origin))),
  methods: ["GET", "POST", "PUT", "DELETE"], allowedHeaders: ["Content-Type", "Authorization"]
}));
app.use(express.json({ limit: "2mb" })); // A foto (data-URL) chega a ~1 MB

const limite = (max, minutos) => rateLimit({
  windowMs: minutos * 60e3, max, standardHeaders: true, legacyHeaders: false,
  handler: (req, res) => res.status(429).json({ erro: "Muitas tentativas. Aguarde alguns minutos e tente de novo." })
});

app.get(["/health", "/api/health"], wrap(async (req, res) => { await pool.query("SELECT 1"); res.json({ ok: true, banco: true }); })); // /health é o caminho usado no Render

// ===== /api/auth =====
const auth = express.Router();
auth.use(limite(30, 15));

auth.post("/login/aluno", wrap(async (req, res) => {
  const u = await autenticar("alunos", req.body.email, req.body.senha);
  res.json({ token: assinar("aluno", u.id),
    usuario: { email: u.email, nome: u.nome, turma: u.turma, matricula: u.matricula } });
}));

auth.post("/login/professor", wrap(async (req, res) => {
  const u = await autenticar("professores", req.body.email, req.body.senha);
  res.json({ token: assinar("professor", u.id), professor: { nome: u.nome, email: u.email } });
}));

auth.post("/cadastro/aluno", wrap(async (req, res) => {
  const { nome, email, cpf } = pessoa(req.body); // cpf pode ser null
  const turma = txt(req.body.turma, 30);
  if (!turma) throw new Erro(400, "Informe a turma.");
  if (!senhaOk(req.body.senha)) throw new Erro(400, "A senha deve ter de 8 a 72 caracteres.");
  await criarAluno({ nome, email, cpf, turma, matricula: await gerarMatricula(), senha: req.body.senha });
  res.status(201).json({ mensagem: "Conta de aluno criada com sucesso!" });
}));

auth.post("/cadastro/professor", wrap(async (req, res) => {
  const { nome, email, cpf } = pessoa(req.body); // sem código da escola; cpf pode ser null
  const disciplina = txt(req.body.disciplina, 80);
  if (!disciplina) throw new Erro(400, "Informe a disciplina.");
  if (!senhaOk(req.body.senha)) throw new Erro(400, "A senha deve ter de 8 a 72 caracteres.");
  await pool.query("INSERT INTO professores (nome, email, cpf, disciplina, senha_hash) VALUES (?,?,?,?,?)",
    [nome, email, cpf, disciplina, await hashSenha(req.body.senha)]);
  res.status(201).json({ mensagem: "Conta de professor criada com sucesso!" });
}));

auth.post("/esqueci-senha", wrap(async (req, res) => {
  const email = txt(req.body.email, 150).toLowerCase();
  if (!emailOk(email)) throw new Erro(400, "Informe um e-mail válido.");
  enviarRecuperacao(email).catch(e => console.error("Falha na recuperação:", e.message)); // Sem await: resposta igual haja ou não cadastro
  res.json({ mensagem: "Se os dados estiverem corretos, você receberá as instruções por e-mail." });
}));

auth.post("/redefinir-senha", wrap(async (req, res) => {
  const { token, novaSenha } = req.body;
  if (typeof token !== "string" || !/^[a-f0-9]{64}$/.test(token)) throw new Erro(400, "Link inválido ou expirado.");
  if (!senhaOk(novaSenha)) throw new Erro(400, "A senha deve ter de 8 a 72 caracteres.");
  const hash = crypto.createHash("sha256").update(token).digest("hex");
  const novoHash = await hashSenha(novaSenha);
  await transacao(async c => {
    const [[t]] = await c.query(
      "SELECT id, tipo, usuario_id FROM redefinicoes_senha WHERE token_hash = ? AND usado = 0 AND expira_em > UTC_TIMESTAMP() FOR UPDATE", [hash]);
    if (!t) throw new Erro(400, "Link inválido ou expirado. Solicite uma nova recuperação.");
    await c.query(`UPDATE ${t.tipo === "aluno" ? "alunos" : "professores"} SET senha_hash = ? WHERE id = ?`, [novoHash, t.usuario_id]);
    await c.query("UPDATE redefinicoes_senha SET usado = 1 WHERE tipo = ? AND usuario_id = ?", [t.tipo, t.usuario_id]); // Invalida todos os links pendentes
  });
  res.json({ mensagem: "Senha alterada com sucesso. Você já pode entrar." });
}));
app.use("/api/auth", auth);

// ===== /api/aluno =====
const aluno = express.Router();
aluno.use(exigir("aluno"));

aluno.get("/perfil", wrap(async (req, res) => {
  const [[a]] = await pool.query("SELECT nome, email, turma, matricula, foto FROM alunos WHERE id = ?", [req.usuario.id]);
  if (!a) throw new Erro(404, "Aluno não encontrado.");
  res.json(a);
}));

aluno.put("/foto", wrap(async (req, res) => {
  const { foto } = req.body;
  if (foto !== null && !(typeof foto === "string" && foto.length <= 1.4e6 && /^data:image\/(jpeg|png|webp);base64,[A-Za-z0-9+/=]+$/.test(foto)))
    throw new Erro(400, "Imagem inválida ou grande demais (máximo ~1 MB).");
  await pool.query("UPDATE alunos SET foto = ? WHERE id = ?", [foto, req.usuario.id]);
  res.json({ mensagem: "Foto atualizada." });
}));

aluno.get("/desempenho", wrap(async (req, res) => {
  const id = req.usuario.id, ds = await discs();
  const [[mensais], [faltas], [bims], [documentos]] = await Promise.all([
    pool.query("SELECT ano, disciplina_id, mes AS idx, nota AS valor FROM notas_mensais WHERE aluno_id = ?", [id]),
    pool.query("SELECT ano, disciplina_id, mes AS idx, faltas AS valor FROM faltas_mensais WHERE aluno_id = ?", [id]),
    pool.query("SELECT ano, disciplina_id, bimestre - 1 AS idx, nota AS valor FROM notas_bimestrais WHERE aluno_id = ?", [id]),
    pool.query("SELECT nome, situacao, data_entrega AS data FROM documentos WHERE aluno_id = ? ORDER BY id", [id])
  ]);
  const anos = [...new Set([...mensais, ...faltas, ...bims].map(l => l.ano))].sort();
  const doAno = (l, a) => l.filter(x => x.ano === a);
  const dados = {}, bimestres = {};
  anos.forEach(a => {
    dados[a] = { notas: matriz(ds, doAno(mensais, a), 10), faltas: matriz(ds, doAno(faltas, a), 10) };
    bimestres[a] = matriz(ds, doAno(bims, a), 3);
  });
  res.json({ meses: MESES, disciplinas: ds.map(d => d.nome),
    aulasPorMes: Object.fromEntries(ds.map(d => [d.nome, d.aulas_por_mes])), dados, bimestres, documentos });
}));
app.use("/api/aluno", aluno);

// ===== /api/professor =====
const prof = express.Router();
prof.use(exigir("professor"));
const idParam = v => { const n = Number(v); if (!Number.isInteger(n) || n < 1) throw new Erro(400, "Identificador inválido."); return n; };
const COLS = "id, nome, email, turma, matricula";

prof.get("/anos", wrap(async (req, res) => {
  const [r] = await pool.query("SELECT ano FROM anos_letivos ORDER BY ano");
  res.json({ anos: r.map(x => x.ano) });
}));

prof.post("/anos", wrap(async (req, res) => {
  const ano = Number(req.body.ano);
  if (!Number.isInteger(ano) || ano < 2000 || ano > 2100) throw new Erro(400, "Ano inválido.");
  const [r] = await pool.query("INSERT IGNORE INTO anos_letivos (ano) VALUES (?)", [ano]);
  if (!r.affectedRows) throw new Erro(409, "Este ano letivo já existe.");
  res.status(201).json({ ano });
}));

prof.get("/alunos", wrap(async (req, res) => {
  const [alunos] = await pool.query(`SELECT ${COLS} FROM alunos ORDER BY nome`);
  res.json({ alunos });
}));

prof.post("/alunos", wrap(async (req, res) => {
  const { nome, email, cpf } = pessoa(req.body);
  const turma = txt(req.body.turma, 30), matricula = txt(req.body.matricula, 30);
  if (!turma || !matricula) throw new Erro(400, "Informe turma e matrícula.");
  let senha = req.body.senha, provisoria = null;
  if (senha === undefined || senha === "") senha = provisoria = senhaAleatoria();
  else if (!senhaOk(senha)) throw new Erro(400, "A senha deve ter de 8 a 72 caracteres.");
  const id = await criarAluno({ nome, email, cpf, turma, matricula, senha });
  const out = { aluno: { id, nome, email, turma, matricula } };
  if (provisoria) out.senhaProvisoria = provisoria; // Mostrada uma única vez ao professor
  res.status(201).json(out);
}));

prof.put("/alunos/:id", wrap(async (req, res) => {
  const id = idParam(req.params.id);
  const { nome, email, cpf } = pessoa(req.body);
  const turma = txt(req.body.turma, 30), matricula = txt(req.body.matricula, 30);
  if (!turma || !matricula) throw new Erro(400, "Informe turma e matrícula.");
  let sql = "UPDATE alunos SET nome=?, email=?, turma=?, matricula=?";
  const p = [nome, email, turma, matricula];
  if (cpf) { sql += ", cpf=?"; p.push(cpf); } // CPF vazio = mantém o atual
  await pool.query(sql + " WHERE id=?", [...p, id]);
  const [[a]] = await pool.query(`SELECT ${COLS} FROM alunos WHERE id = ?`, [id]);
  if (!a) throw new Erro(404, "Aluno não encontrado.");
  res.json({ aluno: a });
}));

prof.delete("/alunos/:id", wrap(async (req, res) => {
  const [r] = await pool.query("DELETE FROM alunos WHERE id = ?", [idParam(req.params.id)]); // Cascata apaga notas, faltas e documentos
  if (!r.affectedRows) throw new Erro(404, "Aluno não encontrado.");
  res.json({ mensagem: "Aluno excluído." });
}));

async function alunoEAno(req, c = pool) {
  const id = idParam(req.params.id), ano = idParam(req.params.ano);
  const [[a]] = await c.query("SELECT id FROM alunos WHERE id = ?", [id]);
  if (!a) throw new Erro(404, "Aluno não encontrado.");
  const [[y]] = await c.query("SELECT ano FROM anos_letivos WHERE ano = ?", [ano]);
  if (!y) throw new Erro(404, "Ano letivo não encontrado.");
  return { id, ano };
}

prof.get("/alunos/:id/lancamentos/:ano", wrap(async (req, res) => {
  const { id, ano } = await alunoEAno(req), ds = await discs(), q = [id, ano];
  const [[mensais], [faltas], [bims], [documentos]] = await Promise.all([
    pool.query("SELECT disciplina_id, mes AS idx, nota AS valor FROM notas_mensais WHERE aluno_id=? AND ano=?", q),
    pool.query("SELECT disciplina_id, mes AS idx, faltas AS valor FROM faltas_mensais WHERE aluno_id=? AND ano=?", q),
    pool.query("SELECT disciplina_id, bimestre - 1 AS idx, nota AS valor FROM notas_bimestrais WHERE aluno_id=? AND ano=?", q),
    pool.query("SELECT nome, situacao, data_entrega AS data FROM documentos WHERE aluno_id=? ORDER BY id", [id])
  ]);
  res.json({ bim: matriz(ds, bims, 3), notas: matriz(ds, mensais, 10), faltas: matriz(ds, faltas, 10), documentos,
    aulasPorMes: Object.fromEntries(ds.map(d => [d.nome, d.aulas_por_mes])) });
}));

// Valida { disciplina: [valores] } e devolve as linhas prontas para o INSERT.
function linhasDe(obj, n, tipo, ds, id, ano) {
  if (!obj || typeof obj !== "object") throw new Erro(400, "Dados inválidos.");
  const out = [];
  for (const d of ds) {
    const arr = obj[d.nome];
    if (!Array.isArray(arr) || arr.length !== n) throw new Erro(400, `Lista inválida para ${d.nome}.`); // Exige tudo: evita apagar dados por engano
    arr.forEach((v, i) => {
      if (v === null || v === "") return;
      const x = Number(v), max = tipo === "falta" ? d.aulas_por_mes : 10;
      if (!Number.isFinite(x) || x < 0 || x > max || (tipo === "falta" && !Number.isInteger(x)))
        throw new Erro(400, `Valor inválido em ${d.nome}.`);
      out.push([id, ano, d.id, tipo === "bim" ? i + 1 : i, tipo === "falta" ? x : Math.round(x * 10) / 10]);
    });
  }
  return out;
}

prof.put("/alunos/:id/lancamentos/:ano", wrap(async (req, res) => {
  const { id, ano } = await alunoEAno(req), ds = await discs(), b = req.body;
  const bim = linhasDe(b.bim, 3, "bim", ds, id, ano);
  const notas = linhasDe(b.notas, 10, "nota", ds, id, ano);
  const faltas = linhasDe(b.faltas, 10, "falta", ds, id, ano);
  const docs = Array.isArray(b.documentos) ? b.documentos : [];
  docs.forEach(d => {
    if (!SITUACOES.includes(d.situacao) || (d.data && !(/^\d{4}-\d{2}-\d{2}$/.test(d.data) && !isNaN(Date.parse(d.data)))))
      throw new Erro(400, "Documento inválido.");
  });
  await transacao(async c => {
    for (const [tabela, coluna, linhas] of [["notas_bimestrais", "bimestre, nota", bim], ["notas_mensais", "mes, nota", notas], ["faltas_mensais", "mes, faltas", faltas]]) {
      await c.query(`DELETE FROM ${tabela} WHERE aluno_id=? AND ano=?`, [id, ano]); // Regrava o ano inteiro (null = sem linha)
      if (linhas.length) await c.query(`INSERT INTO ${tabela} (aluno_id, ano, disciplina_id, ${coluna}) VALUES ?`, [linhas]);
    }
    for (const d of docs)
      await c.query("UPDATE documentos SET situacao=?, data_entrega=? WHERE aluno_id=? AND nome=?", [d.situacao, d.data || null, id, d.nome]);
  });
  res.json({ mensagem: "Lançamentos salvos." });
}));
app.use("/api/professor", prof);

// ===== /api/secretaria (público) =====
const sec = express.Router();
sec.use(limite(20, 60));

sec.post("/solicitacoes", wrap(async (req, res) => {
  const b = req.body, nome = txt(b.nome, 120), email = txt(b.email, 150).toLowerCase(), documento = txt(b.documento, 60);
  if (nome.length < 3 || !emailOk(email)) throw new Erro(400, "Informe nome e e-mail válidos.");
  if (!DOCS_SECRETARIA.includes(documento)) throw new Erro(400, "Escolha o documento desejado.");
  const protocolo = `EDU-${new Date().getFullYear()}-${crypto.randomBytes(5).toString("hex").toUpperCase()}`;
  await pool.query("INSERT INTO solicitacoes (protocolo, nome, email, matricula, documento, detalhes) VALUES (?,?,?,?,?,?)",
    [protocolo, nome, email, txt(b.matricula, 30) || null, documento, txt(b.detalhes, 1000) || null]);
  res.status(201).json({ protocolo });
}));

sec.get("/solicitacoes/:protocolo", wrap(async (req, res) => {
  if (!/^EDU-\d{4}-[A-F0-9]{10}$/.test(req.params.protocolo)) throw new Erro(404, "Protocolo não encontrado.");
  const [[s]] = await pool.query("SELECT protocolo, documento, status, criado_em AS data FROM solicitacoes WHERE protocolo = ?", [req.params.protocolo]);
  if (!s) throw new Erro(404, "Protocolo não encontrado.");
  res.json(s); // Não expõe nome nem e-mail
}));
app.use("/api/secretaria", sec);

// ---------- Erros ----------
app.use("/api", (req, res) => res.status(404).json({ erro: "Rota não encontrada." }));
app.use((err, req, res, next) => {
  if (err.type === "entity.parse.failed") return res.status(400).json({ erro: "JSON inválido." });
  if (err.type === "entity.too.large") return res.status(413).json({ erro: "Dados grandes demais." });
  if (err.code === "ER_DUP_ENTRY") return res.status(409).json({ erro: "Já existe um cadastro com este e-mail, CPF ou matrícula." });
  if (err.status) return res.status(err.status).json({ erro: err.message });
  console.error(`[ERRO ${req.method} ${req.originalUrl}] código=${err.code || "-"} | ${err.sqlMessage || err.message}`); // Mostra a causa real no log do Render
  console.error(err.stack);
  // Problemas de banco (tabela/coluna ausente, coluna NOT NULL antiga, senha ou host errados): mensagem que aponta o caminho da correção
  const ESQUEMA = ["ER_NO_SUCH_TABLE", "ER_BAD_FIELD_ERROR", "ER_BAD_NULL_ERROR", "ER_NO_DEFAULT_FOR_FIELD", "ER_DATA_TOO_LONG", "ER_WARN_DATA_OUT_OF_RANGE"];
  const CONEXAO = ["ECONNREFUSED", "ETIMEDOUT", "ENOTFOUND", "ER_ACCESS_DENIED_ERROR", "ER_DBACCESS_DENIED_ERROR", "ER_BAD_DB_ERROR", "PROTOCOL_CONNECTION_LOST"];
  if (ESQUEMA.includes(err.code)) return res.status(500).json({ erro: "O banco de dados está desatualizado. Importe novamente o schema.sql (veja o log do servidor)." });
  if (CONEXAO.includes(err.code)) return res.status(500).json({ erro: "Não foi possível acessar o banco de dados. Confira as variáveis DB_* do servidor (veja o log)." });
  res.status(500).json({ erro: "Erro interno do servidor." });
});

const porta = Number(process.env.PORT) || 3000;
app.listen(porta, async () => {
  console.log(`API EduConnect na porta ${porta}`);
  try { await pool.query("SELECT 1"); console.log("Banco conectado."); }
  catch (e) { console.error("Falha ao conectar no banco:", e.message); }
});
