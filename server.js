'use strict'; // Ativa o modo estrito do JavaScript (evita erros silenciosos)

// =====================================================================
// 1. IMPORTAÇÕES
// =====================================================================
require('dotenv').config(); // Lê o arquivo .env (uso local) e carrega as variáveis em process.env
const express = require('express'); // Framework que cria o servidor web e as rotas da API
const cors = require('cors'); // Controla quais sites (origens) podem chamar a API
const helmet = require('helmet'); // Adiciona cabeçalhos HTTP de segurança
const rateLimit = require('express-rate-limit'); // Limita a quantidade de requisições por IP
const mysql = require('mysql2/promise'); // Driver que conecta ao MariaDB/MySQL usando async/await
const bcrypt = require('bcryptjs'); // Gera e confere hashes de senha (versão em JavaScript puro)
const jwt = require('jsonwebtoken'); // Cria e valida tokens de login (JWT)
const crypto = require('crypto'); // Módulo nativo do Node para números aleatórios e SHA-256

// =====================================================================
// 2. CONFIGURAÇÕES (todas vêm das variáveis de ambiente)
// =====================================================================
const PORT = process.env.PORT || 3000; // Porta do servidor (o Render define PORT automaticamente)
const JWT_SECRET = process.env.JWT_SECRET; // Segredo usado para assinar os tokens de login
if (!JWT_SECRET || JWT_SECRET.length < 32) { // Se o segredo não existir ou for curto demais...
  console.error('ERRO: defina JWT_SECRET com pelo menos 32 caracteres.'); // ...avisa no log
  process.exit(1); // ...e encerra o programa (não é seguro iniciar assim)
} // Fecha a verificação do segredo
const ORIGENS = (process.env.CORS_ORIGINS || '') // Lê a lista de sites autorizados (separados por vírgula)
  .split(',') // Separa a lista em pedaços
  .map(o => o.trim().replace(/\/$/, '')) // Remove espaços e a barra final de cada endereço
  .filter(Boolean); // Descarta itens vazios
const FRONTEND_URL = (process.env.FRONTEND_URL || ORIGENS[0] || '').replace(/\/$/, ''); // Endereço base do site (usado no link do e-mail)
const MESES_LETIVOS = [2, 3, 4, 5, 6, 8, 9, 10, 11, 12]; // Meses letivos na ordem do front (Fev...Dez, sem julho)
const N_BIM = 3; // Quantidade de bimestres exibidos no perfil
const TIPOS_SITUACAO = ['entregue', 'analise', 'pendente']; // Situações válidas de um documento
const DOCUMENTOS_SECRETARIA = ['Declaração de matrícula', 'Histórico escolar', 'Atestado de frequência', 'Outro assunto']; // Opções do formulário da secretaria

// =====================================================================
// 3. CONEXÃO COM O BANCO (pool = conjunto de conexões reaproveitadas)
// =====================================================================
const pool = mysql.createPool({ // Cria o pool de conexões
  host: process.env.DB_HOST, // Servidor do banco (ex.: mysql-sua-conta.alwaysdata.net)
  port: Number(process.env.DB_PORT || 3306), // Porta do banco (padrão 3306)
  user: process.env.DB_USER, // Usuário do banco
  password: process.env.DB_PASSWORD, // Senha do banco
  database: process.env.DB_NAME, // Nome do banco (no AlwaysData começa com o nome da conta)
  waitForConnections: true, // Se todas as conexões estiverem ocupadas, espera em fila
  connectionLimit: Number(process.env.DB_POOL || 5), // Máximo de conexões simultâneas (plano gratuito tem limite baixo)
  queueLimit: 0, // Fila de espera sem limite
  charset: 'utf8mb4', // Acentos e emojis corretos
  dateStrings: true, // Devolve datas como texto "AAAA-MM-DD" (sem problema de fuso)
  decimalNumbers: true // Devolve DECIMAL como número (e não como texto)
}); // Fecha a configuração do pool

// =====================================================================
// 4. APLICATIVO EXPRESS E MIDDLEWARES GLOBAIS
// =====================================================================
const app = express(); // Cria o aplicativo Express
app.set('trust proxy', 1); // Confia no proxy do Render para enxergar o IP real do visitante
app.use(helmet()); // Ativa os cabeçalhos de segurança
app.use(cors({ // Configura o CORS (comunicação entre GitHub Pages e esta API)
  origin: (origem, retorno) => { // Função que decide se a origem da requisição é permitida
    if (!origem || ORIGENS.includes(origem)) return retorno(null, true); // Sem origem (Postman/health check) ou na lista: permite
    const erro = new Error('Origem não permitida pelo CORS.'); // Cria o erro de bloqueio
    erro.status = 403; // Marca como "proibido"
    return retorno(erro); // Bloqueia a requisição
  }, // Fecha a função de origem
  methods: ['GET', 'POST', 'PUT', 'DELETE'], // Métodos HTTP aceitos
  allowedHeaders: ['Content-Type', 'Authorization'], // Cabeçalhos que o front pode enviar
  maxAge: 86400 // O navegador guarda a resposta do "preflight" por 24 horas
})); // Fecha a configuração do CORS
app.use(express.json({ limit: '2mb' })); // Lê o corpo JSON das requisições (limite de 2 MB, por causa da foto)

const limiteGeral = rateLimit({ // Limite geral de uso da API
  windowMs: 15 * 60 * 1000, // Janela de 15 minutos
  limit: 300, // Máximo de 300 requisições por IP na janela
  standardHeaders: true, // Informa o limite nos cabeçalhos padrão
  legacyHeaders: false, // Desliga os cabeçalhos antigos
  message: { erro: 'Muitas requisições. Tente novamente em alguns minutos.' } // Mensagem ao exceder
}); // Fecha limiteGeral
const limiteAuth = rateLimit({ // Limite rígido para login e recuperação de senha (contra força bruta)
  windowMs: 15 * 60 * 1000, // Janela de 15 minutos
  limit: 20, // Máximo de 20 tentativas por IP na janela
  standardHeaders: true, // Cabeçalhos padrão
  legacyHeaders: false, // Sem cabeçalhos antigos
  message: { erro: 'Muitas tentativas. Aguarde alguns minutos e tente de novo.' } // Mensagem ao exceder
}); // Fecha limiteAuth
const limiteSecretaria = rateLimit({ // Limite para o formulário público da secretaria (contra spam)
  windowMs: 60 * 60 * 1000, // Janela de 1 hora
  limit: 10, // Máximo de 10 solicitações por IP na janela
  standardHeaders: true, // Cabeçalhos padrão
  legacyHeaders: false, // Sem cabeçalhos antigos
  message: { erro: 'Limite de solicitações atingido. Tente novamente mais tarde.' } // Mensagem ao exceder
}); // Fecha limiteSecretaria
app.use('/api', limiteGeral); // Aplica o limite geral a todas as rotas que começam com /api

// =====================================================================
// 5. FUNÇÕES AUXILIARES
// =====================================================================
class ErroHttp extends Error { // Erro com código HTTP (400, 401, 404...) para responder ao front
  constructor(status, mensagem) { // Recebe o código e o texto do erro
    super(mensagem); // Guarda a mensagem na classe Error
    this.status = status; // Guarda o código HTTP
  } // Fecha o construtor
} // Fecha a classe ErroHttp

const assincrono = fn => (req, res, next) => // Envolve rotas async para que erros cheguem ao tratador de erros
  Promise.resolve(fn(req, res, next)).catch(next); // Se a rota falhar, repassa o erro ao Express

const sha256 = texto => crypto.createHash('sha256').update(texto).digest('hex'); // Gera o hash SHA-256 (usado nos tokens de recuperação)

const EMAIL_RE = /^[^\s@]+@[^\s@]+\.[^\s@]+$/; // Padrão simples de e-mail válido
const DATA_RE = /^\d{4}-\d{2}-\d{2}$/; // Padrão de data AAAA-MM-DD

const soDigitos = v => String(v ?? '').replace(/\D/g, ''); // Remove tudo que não é número (ex.: pontos do CPF)

function cpfValido(valor) { // Confere o CPF pelos dígitos verificadores (mesma regra do front)
  const n = soDigitos(valor); // Deixa só os números
  if (n.length !== 11 || /^(\d)\1{10}$/.test(n)) return false; // Exige 11 dígitos e rejeita sequências iguais (111.111...)
  for (let t = 9; t < 11; t++) { // Calcula os dois dígitos verificadores
    let soma = 0; // Acumulador da soma ponderada
    for (let i = 0; i < t; i++) soma += Number(n[i]) * (t + 1 - i); // Soma cada dígito vezes seu peso
    const digito = ((soma * 10) % 11) % 10; // Dígito esperado
    if (digito !== Number(n[t])) return false; // Se não bater, o CPF é inválido
  } // Fecha o laço dos dígitos verificadores
  return true; // Passou em todas as conferências
} // Fecha cpfValido

function exigirTexto(valor, rotulo, max) { // Valida um texto obrigatório e devolve já sem espaços nas pontas
  const t = typeof valor === 'string' ? valor.trim() : ''; // Só aceita texto; remove espaços extras
  if (!t) throw new ErroHttp(400, `Informe: ${rotulo}.`); // Vazio: erro 400
  if (t.length > max) throw new ErroHttp(400, `${rotulo} excede ${max} caracteres.`); // Longo demais: erro 400
  return t; // Devolve o texto validado
} // Fecha exigirTexto

function textoOpcional(valor, rotulo, max) { // Valida um texto opcional (vazio vira null)
  if (valor === undefined || valor === null || String(valor).trim() === '') return null; // Sem valor: devolve null
  return exigirTexto(String(valor), rotulo, max); // Com valor: aplica as mesmas regras do obrigatório
} // Fecha textoOpcional

function idDaRota(valor) { // Converte o :id da URL em número inteiro positivo
  const n = Number(valor); // Tenta converter para número
  if (!Number.isInteger(n) || n <= 0) throw new ErroHttp(400, 'Identificador inválido.'); // Se não for válido, erro 400
  return n; // Devolve o número
} // Fecha idDaRota

function hojeISO() { // Data de hoje (fuso de São Paulo) no formato AAAA-MM-DD
  return new Date().toLocaleDateString('en-CA', { timeZone: 'America/Sao_Paulo' }); // O formato "en-CA" já sai como AAAA-MM-DD
} // Fecha hojeISO

function erroDuplicado(err) { // Converte erro de "valor repetido" do banco em mensagem amigável
  if (err && err.code === 'ER_DUP_ENTRY') { // Só trata o erro de duplicidade
    const chave = (/for key '([^']+)'/.exec(String(err.sqlMessage || '')) || [])[1] || ''; // Descobre qual coluna repetiu
    if (chave.includes('matricula')) return new ErroHttp(409, 'Já existe um aluno com esta matrícula.'); // Matrícula repetida
    if (chave.includes('email')) return new ErroHttp(409, 'Já existe um usuário com este e-mail.'); // E-mail repetido
    if (chave.includes('cpf')) return new ErroHttp(409, 'Já existe um usuário com este CPF.'); // CPF repetido
    return new ErroHttp(409, 'Registro duplicado.'); // Outra duplicidade qualquer
  } // Fecha o if de duplicidade
  return err; // Qualquer outro erro segue sem alteração
} // Fecha erroDuplicado

async function comTransacao(trabalho) { // Executa vários comandos como um bloco: ou grava tudo, ou nada
  const conn = await pool.getConnection(); // Pega uma conexão exclusiva do pool
  try { // Tenta executar o trabalho
    await conn.beginTransaction(); // Inicia a transação
    const resultado = await trabalho(conn); // Executa os comandos recebidos
    await conn.commit(); // Confirma tudo no banco
    return resultado; // Devolve o que o trabalho retornou
  } catch (e) { // Se algo falhar...
    await conn.rollback().catch(() => {}); // ...desfaz tudo o que foi feito
    throw e; // ...e repassa o erro
  } finally { // Aconteça o que acontecer...
    conn.release(); // ...devolve a conexão ao pool
  } // Fecha try/catch/finally
} // Fecha comTransacao

// ---------- Disciplinas (lidas uma vez e guardadas em memória) ----------
let cacheDisciplinas = null; // Guarda a lista de disciplinas depois da primeira leitura
async function disciplinas() { // Devolve [{ id, nome, aulas }] na ordem do cadastro
  if (!cacheDisciplinas) { // Se ainda não foi lida...
    const [linhas] = await pool.query('SELECT id, nome, aulas_por_mes AS aulas FROM disciplinas ORDER BY id'); // ...busca no banco
    cacheDisciplinas = linhas; // ...e guarda em memória
  } // Fecha o if do cache
  return cacheDisciplinas; // Devolve a lista
} // Fecha disciplinas

function estruturaVazia(discs) { // Cria o formato que o front espera, com tudo null (= não lançado)
  const e = { bim: {}, notas: {}, faltas: {} }; // Três grupos de dados
  discs.forEach(d => { // Para cada disciplina...
    e.bim[d.nome] = Array(N_BIM).fill(null); // ...bimestres vazios
    e.notas[d.nome] = Array(MESES_LETIVOS.length).fill(null); // ...notas mensais vazias
    e.faltas[d.nome] = Array(MESES_LETIVOS.length).fill(null); // ...faltas mensais vazias
  }); // Fecha o forEach
  return e; // Devolve a estrutura pronta
} // Fecha estruturaVazia

async function buscarLancamentos(alunoId, ano) { // Lê notas e faltas do aluno (de um ano ou de todos se ano for null)
  const discs = await disciplinas(); // Lista de disciplinas
  const nomePorId = new Map(discs.map(d => [d.id, d.nome])); // Mapa id -> nome da disciplina
  const filtro = ano ? ' AND ano = ?' : ''; // Acrescenta o filtro de ano só quando necessário
  const params = ano ? [alunoId, ano] : [alunoId]; // Parâmetros correspondentes ao filtro
  const [bim] = await pool.query('SELECT ano, disciplina_id, bimestre, nota FROM notas_bimestrais WHERE aluno_id = ?' + filtro, params); // Notas bimestrais
  const [mes] = await pool.query('SELECT ano, disciplina_id, mes, nota FROM notas_mensais WHERE aluno_id = ?' + filtro, params); // Notas mensais
  const [fal] = await pool.query('SELECT ano, disciplina_id, mes, quantidade FROM faltas_mensais WHERE aluno_id = ?' + filtro, params); // Faltas mensais
  const anos = {}; // Resultado: { "2026": { bim, notas, faltas } }
  const garantir = a => (anos[a] = anos[a] || estruturaVazia(discs)); // Cria o ano na primeira vez que aparece
  if (ano) garantir(ano); // Se um ano foi pedido, ele sempre existe no resultado (mesmo vazio)
  bim.forEach(r => { garantir(r.ano).bim[nomePorId.get(r.disciplina_id)][r.bimestre - 1] = Number(r.nota); }); // Coloca cada nota bimestral na posição do bimestre
  mes.forEach(r => { // Para cada nota mensal...
    const pos = MESES_LETIVOS.indexOf(r.mes); // ...descobre a posição do mês (fev = 0 ... dez = 9)
    if (pos >= 0) garantir(r.ano).notas[nomePorId.get(r.disciplina_id)][pos] = Number(r.nota); // ...e grava a nota
  }); // Fecha o forEach das notas mensais
  fal.forEach(r => { // Para cada registro de faltas...
    const pos = MESES_LETIVOS.indexOf(r.mes); // ...descobre a posição do mês
    if (pos >= 0) garantir(r.ano).faltas[nomePorId.get(r.disciplina_id)][pos] = Number(r.quantidade); // ...e grava a quantidade
  }); // Fecha o forEach das faltas
  return anos; // Devolve todos os anos montados
} // Fecha buscarLancamentos

async function buscarDocumentos(alunoId) { // Lê a situação dos 8 documentos exigidos para o aluno
  const [linhas] = await pool.query( // Consulta com LEFT JOIN: tipos sem registro aparecem como pendentes
    'SELECT dt.nome, da.situacao, da.data_entrega AS data FROM documentos_tipos dt ' + // Todos os tipos de documento
    'LEFT JOIN documentos_aluno da ON da.tipo_id = dt.id AND da.aluno_id = ? ' + // Situação deste aluno (se existir)
    'ORDER BY dt.ordem', [alunoId]); // Mesma ordem exibida no site
  return linhas.map(l => ({ nome: l.nome, situacao: l.situacao || 'pendente', data: l.data || null })); // Formato do front
} // Fecha buscarDocumentos

async function dadosAluno(usuarioId) { // Busca perfil escolar a partir do id do usuário logado
  const [linhas] = await pool.execute( // Consulta preparada (segura contra SQL injection)
    'SELECT a.id, a.matricula, a.foto, t.nome AS turma, u.nome, u.email ' + // Campos que o perfil mostra
    'FROM alunos a JOIN usuarios u ON u.id = a.usuario_id JOIN turmas t ON t.id = a.turma_id ' + // Junta aluno, usuário e turma
    'WHERE a.usuario_id = ?', [usuarioId]); // Filtra pelo usuário
  if (!linhas[0]) throw new ErroHttp(404, 'Cadastro de aluno não encontrado.'); // Sem aluno: erro 404
  return linhas[0]; // Devolve os dados do aluno
} // Fecha dadosAluno

// ---------- E-mail (via API HTTPS da Brevo; o Render gratuito bloqueia SMTP) ----------
async function enviarEmail(para, assunto, texto) { // Envia um e-mail de texto simples
  if (!process.env.BREVO_API_KEY) { // Se a chave da Brevo não foi configurada...
    if (process.env.NODE_ENV !== 'production') console.log(`[E-MAIL SIMULADO] Para: ${para}\n${assunto}\n${texto}`); // ...só mostra no log (apenas fora de produção)
    return; // ...e não envia nada
  } // Fecha o if da chave
  const resposta = await fetch('https://api.brevo.com/v3/smtp/email', { // Chama a API da Brevo
    method: 'POST', // Método de envio
    headers: { 'api-key': process.env.BREVO_API_KEY, 'Content-Type': 'application/json' }, // Autenticação e tipo do conteúdo
    body: JSON.stringify({ // Corpo da mensagem
      sender: { name: process.env.EMAIL_NOME || 'EduConnect', email: process.env.EMAIL_REMETENTE }, // Remetente (precisa estar verificado na Brevo)
      to: [{ email: para }], // Destinatário
      subject: assunto, // Assunto
      textContent: texto // Texto da mensagem
    }) // Fecha o JSON.stringify
  }); // Fecha o fetch
  if (!resposta.ok) throw new Error('Falha no envio de e-mail: HTTP ' + resposta.status); // Se a Brevo recusar, lança erro
} // Fecha enviarEmail

// ---------- Autenticação por token JWT ----------
function emitirToken(usuario) { // Cria o token de login do usuário
  return jwt.sign( // Assina o token
    { sub: usuario.id, perfil: usuario.perfil, nome: usuario.nome }, // Dados guardados dentro do token
    JWT_SECRET, // Segredo da assinatura
    { expiresIn: process.env.JWT_EXPIRA || '8h', algorithm: 'HS256' } // Validade de 8 horas por padrão
  ); // Fecha jwt.sign
} // Fecha emitirToken

function exigirPerfil(perfil) { // Middleware: só deixa passar quem tem token válido do perfil indicado
  return (req, res, next) => { // Função executada antes da rota
    const [tipo, token] = (req.headers.authorization || '').split(' '); // Lê "Bearer <token>" do cabeçalho
    if (tipo !== 'Bearer' || !token) return next(new ErroHttp(401, 'Faça login para continuar.')); // Sem token: erro 401
    try { // Tenta validar o token
      const dados = jwt.verify(token, JWT_SECRET, { algorithms: ['HS256'] }); // Confere assinatura e validade
      if (dados.perfil !== perfil) return next(new ErroHttp(403, 'Acesso não permitido para este perfil.')); // Perfil errado: erro 403
      req.usuario = { id: dados.sub, perfil: dados.perfil, nome: dados.nome }; // Disponibiliza o usuário para a rota
      return next(); // Libera o acesso
    } catch (e) { // Token inválido ou expirado
      return next(new ErroHttp(401, 'Sessão expirada. Faça login novamente.')); // Erro 401
    } // Fecha try/catch
  }; // Fecha a função do middleware
} // Fecha exigirPerfil
const soAluno = exigirPerfil('aluno'); // Middleware pronto para rotas do aluno
const soProfessor = exigirPerfil('professor'); // Middleware pronto para rotas do professor

// =====================================================================
// 6. ROTAS PÚBLICAS: SAÚDE DA API
// =====================================================================
app.get('/', (req, res) => res.json({ api: 'EduConnect', status: 'online' })); // Página inicial da API (teste rápido no navegador)

app.get('/health', assincrono(async (req, res) => { // Rota de verificação (o Render pode usá-la como health check)
  try { // Tenta falar com o banco
    await pool.query('SELECT 1'); // Consulta mínima
    res.json({ ok: true, banco: true }); // Tudo certo
  } catch (e) { // Se o banco não responder...
    res.status(503).json({ ok: false, banco: false }); // ...informa indisponibilidade
  } // Fecha try/catch
})); // Fecha /health

// =====================================================================
// 7. ROTAS DE AUTENTICAÇÃO
// =====================================================================
function loginPara(perfil) { // Fábrica: cria o tratador de login para "aluno" ou "professor"
  return assincrono(async (req, res) => { // Devolve a rota já protegida contra erros assíncronos
    const email = String(req.body.email || '').trim().toLowerCase(); // E-mail digitado, sem espaços e em minúsculas
    const senha = String(req.body.senha || ''); // Senha digitada
    if (!EMAIL_RE.test(email) || !senha) throw new ErroHttp(400, 'Informe e-mail e senha.'); // Campos inválidos: erro 400
    const [linhas] = await pool.execute( // Busca o usuário ativo com esse perfil
      'SELECT id, nome, email, senha_hash, perfil FROM usuarios WHERE email = ? AND perfil = ? AND ativo = 1', // Consulta preparada
      [email, perfil]); // Valores dos parâmetros
    const usuario = linhas[0]; // Primeiro (e único) resultado, se houver
    const confere = await bcrypt.compare(senha, usuario ? usuario.senha_hash : HASH_FALSO); // Compara a senha (gasta o mesmo tempo mesmo se o usuário não existir)
    if (!usuario || !confere) throw new ErroHttp(401, 'E-mail ou senha incorretos.'); // Mensagem única: não revela se o e-mail existe
    const token = emitirToken(usuario); // Gera o token de sessão
    if (perfil === 'aluno') { // Resposta do aluno (mesmo formato de "usuarioLogado" do front)
      const aluno = await dadosAluno(usuario.id); // Busca turma e matrícula
      return res.json({ token, usuario: { email: usuario.email, nome: usuario.nome, turma: aluno.turma, matricula: aluno.matricula } }); // Devolve token e dados
    } // Fecha o if do aluno
    return res.json({ token, professor: { nome: usuario.nome, email: usuario.email } }); // Resposta do professor (formato de "professorLogado")
  }); // Fecha assincrono
} // Fecha loginPara
const HASH_FALSO = bcrypt.hashSync('senha-que-nao-existe', 10); // Hash de mentira usado para igualar o tempo de resposta quando o e-mail não existe

app.post('/api/auth/login/aluno', limiteAuth, loginPara('aluno')); // Login da página login.html
app.post('/api/auth/login/professor', limiteAuth, loginPara('professor')); // Login da página loginProf.html

app.post('/api/auth/esqueci-senha', limiteAuth, assincrono(async (req, res) => { // Página esqueci-senha.html
  const email = String(req.body.email || '').trim().toLowerCase(); // E-mail informado
  const cpf = soDigitos(req.body.cpf); // CPF informado, só com números
  if (!EMAIL_RE.test(email) || !cpfValido(cpf)) throw new ErroHttp(400, 'Informe um e-mail e um CPF válidos.'); // Validação básica
  const resposta = { mensagem: 'Solicitação enviada! Se os dados estiverem corretos, você receberá as instruções por e-mail.' }; // Resposta sempre igual (não revela se a conta existe)
  const [linhas] = await pool.execute('SELECT id, nome FROM usuarios WHERE email = ? AND cpf = ? AND ativo = 1', [email, cpf]); // Procura a conta
  const usuario = linhas[0]; // Conta encontrada (ou undefined)
  if (usuario) { // Só continua se e-mail e CPF baterem
    const token = crypto.randomBytes(32).toString('hex'); // Token aleatório de 64 caracteres (vai só por e-mail)
    await pool.execute('UPDATE tokens_recuperacao SET usado = 1 WHERE usuario_id = ? AND usado = 0', [usuario.id]); // Invalida pedidos anteriores
    await pool.execute( // Guarda apenas o hash do token no banco
      'INSERT INTO tokens_recuperacao (usuario_id, token_hash, expira_em) VALUES (?, ?, DATE_ADD(NOW(), INTERVAL 1 HOUR))', // Validade de 1 hora
      [usuario.id, sha256(token)]); // Valores dos parâmetros
    const link = `${FRONTEND_URL}/pages/redefinir-senha.html?token=${token}`; // Link que o usuário receberá
    try { // Falha no e-mail não deve revelar nada ao visitante
      await enviarEmail(email, 'EduConnect: redefinição de senha', // Envia a mensagem
        `Olá, ${usuario.nome}.\n\nPara criar uma nova senha, acesse o link abaixo (válido por 1 hora):\n${link}\n\nSe não foi você, ignore este e-mail.`); // Texto do e-mail
    } catch (e) { // Se o envio falhar...
      console.error('Falha ao enviar e-mail de recuperação:', e.message); // ...registra no log do servidor
    } // Fecha try/catch do e-mail
  } // Fecha o if do usuário
  res.json(resposta); // Responde sempre com a mesma mensagem
})); // Fecha /esqueci-senha

app.post('/api/auth/redefinir-senha', limiteAuth, assincrono(async (req, res) => { // Conclui a troca de senha com o token do e-mail
  const token = String(req.body.token || ''); // Token recebido do link
  const novaSenha = String(req.body.novaSenha || ''); // Nova senha escolhida
  if (!/^[a-f0-9]{64}$/.test(token)) throw new ErroHttp(400, 'Link inválido ou expirado.'); // Formato do token inválido
  if (novaSenha.length < 8 || novaSenha.length > 72) throw new ErroHttp(400, 'A senha deve ter de 8 a 72 caracteres.'); // 72 é o limite do bcrypt
  const hashNovo = await bcrypt.hash(novaSenha, 10); // Criptografa a nova senha
  await comTransacao(async conn => { // Troca a senha e queima o token de forma atômica
    const [linhas] = await conn.execute( // Procura o token válido e bloqueia a linha
      'SELECT id, usuario_id FROM tokens_recuperacao WHERE token_hash = ? AND usado = 0 AND expira_em > NOW() FOR UPDATE', // Não usado e não expirado
      [sha256(token)]); // Compara pelo hash
    if (!linhas[0]) throw new ErroHttp(400, 'Link inválido ou expirado.'); // Token não encontrado: erro 400
    await conn.execute('UPDATE usuarios SET senha_hash = ? WHERE id = ?', [hashNovo, linhas[0].usuario_id]); // Grava a nova senha
    await conn.execute('UPDATE tokens_recuperacao SET usado = 1 WHERE id = ?', [linhas[0].id]); // Marca o token como usado
  }); // Fecha a transação
  res.json({ mensagem: 'Senha alterada com sucesso. Faça login com a nova senha.' }); // Confirma ao usuário
})); // Fecha /redefinir-senha

// =====================================================================
// 8. ROTAS DO ALUNO (perfil.html e desempenho.html)
// =====================================================================
app.get('/api/aluno/perfil', soAluno, assincrono(async (req, res) => { // Dados do cabeçalho do perfil
  const a = await dadosAluno(req.usuario.id); // Busca o aluno logado
  res.json({ nome: a.nome, email: a.email, turma: a.turma, matricula: a.matricula, foto: a.foto || null }); // Devolve os dados
})); // Fecha /aluno/perfil

app.put('/api/aluno/foto', soAluno, assincrono(async (req, res) => { // Salva (ou remove) a foto de perfil
  const foto = req.body.foto; // Foto enviada em data-URL (base64)
  if (foto !== null) { // null significa "remover a foto"
    const valida = typeof foto === 'string' && foto.length <= 1500000 && /^data:image\/(png|jpeg|webp|gif);base64,[A-Za-z0-9+/=]+$/.test(foto); // Só imagens comuns e até ~1,1 MB
    if (!valida) throw new ErroHttp(400, 'Foto inválida ou grande demais (use PNG, JPG, WEBP ou GIF até ~1 MB).'); // Rejeita o resto (inclui SVG)
  } // Fecha o if da validação
  await pool.execute('UPDATE alunos SET foto = ? WHERE usuario_id = ?', [foto, req.usuario.id]); // Grava a foto
  res.json({ mensagem: 'Foto atualizada.' }); // Confirma
})); // Fecha /aluno/foto

app.get('/api/aluno/desempenho', soAluno, assincrono(async (req, res) => { // Notas, faltas e documentos do aluno
  const aluno = await dadosAluno(req.usuario.id); // Identifica o aluno logado
  const discs = await disciplinas(); // Lista de disciplinas
  const todos = await buscarLancamentos(aluno.id, null); // Lançamentos de todos os anos que têm dados
  if (!Object.keys(todos).length) { // Se o aluno ainda não tem nenhum lançamento...
    const [anos] = await pool.query('SELECT MAX(ano) AS ano FROM anos_letivos'); // ...usa o ano letivo mais recente
    if (anos[0].ano) todos[anos[0].ano] = estruturaVazia(discs); // ...com estrutura vazia (o front não quebra)
  } // Fecha o if dos lançamentos
  const dados = {}; // Formato "DADOS" do front: { ano: { notas, faltas } }
  const bimestres = {}; // Notas bimestrais: { ano: { disciplina: [n1, n2, n3] } }
  Object.entries(todos).forEach(([ano, e]) => { // Separa cada ano nos dois formatos
    dados[ano] = { notas: e.notas, faltas: e.faltas }; // Notas e faltas mensais
    bimestres[ano] = e.bim; // Notas bimestrais
  }); // Fecha o forEach
  res.json({ // Resposta completa
    meses: ['Fev', 'Mar', 'Abr', 'Mai', 'Jun', 'Ago', 'Set', 'Out', 'Nov', 'Dez'], // Rótulos dos meses letivos
    disciplinas: discs.map(d => d.nome), // Nomes das disciplinas (ordem do front)
    aulasPorMes: Object.fromEntries(discs.map(d => [d.nome, d.aulas])), // Aulas mensais de cada disciplina
    dados, // Notas e faltas mensais por ano
    bimestres, // Notas bimestrais por ano
    documentos: await buscarDocumentos(aluno.id) // Situação dos documentos
  }); // Fecha res.json
})); // Fecha /aluno/desempenho

// =====================================================================
// 9. ROTAS DO PROFESSOR (painel-professor.html)
// =====================================================================
app.get('/api/professor/anos', soProfessor, assincrono(async (req, res) => { // Anos letivos cadastrados
  const [linhas] = await pool.query('SELECT ano FROM anos_letivos ORDER BY ano'); // Busca os anos
  res.json({ anos: linhas.map(l => l.ano) }); // Devolve só os números
})); // Fecha GET /anos

app.post('/api/professor/anos', soProfessor, assincrono(async (req, res) => { // Botão "+ Ano"
  const ano = Number(req.body.ano); // Ano informado
  if (!Number.isInteger(ano) || ano < 2000 || ano > 2100) throw new ErroHttp(400, 'Ano inválido.'); // Mesma regra do front
  try { // Tenta inserir
    await pool.execute('INSERT INTO anos_letivos (ano) VALUES (?)', [ano]); // Cadastra o ano
  } catch (e) { // Se já existir...
    if (e.code === 'ER_DUP_ENTRY') throw new ErroHttp(409, 'Este ano letivo já existe.'); // ...avisa
    throw e; // Outros erros seguem adiante
  } // Fecha try/catch
  res.status(201).json({ ano }); // Confirma a criação
})); // Fecha POST /anos

app.get('/api/professor/alunos', soProfessor, assincrono(async (req, res) => { // Lista de alunos do painel
  const [linhas] = await pool.query( // Busca todos os alunos
    'SELECT a.id, u.nome, u.email, t.nome AS turma, a.matricula FROM alunos a ' + // Campos mostrados na lista
    'JOIN usuarios u ON u.id = a.usuario_id JOIN turmas t ON t.id = a.turma_id ORDER BY u.nome'); // Junta tabelas e ordena por nome
  res.json({ alunos: linhas }); // Devolve a lista
})); // Fecha GET /alunos

function lerDadosAluno(corpo, criando) { // Valida os campos do formulário "Novo aluno / Editar aluno"
  const nome = exigirTexto(corpo.nome, 'nome', 120); // Nome obrigatório
  const email = exigirTexto(corpo.email, 'e-mail', 150).toLowerCase(); // E-mail obrigatório, em minúsculas
  if (!EMAIL_RE.test(email)) throw new ErroHttp(400, 'Informe um e-mail válido.'); // Formato do e-mail
  const turma = exigirTexto(corpo.turma, 'turma', 40); // Turma obrigatória
  const matricula = exigirTexto(corpo.matricula, 'matrícula', 30); // Matrícula obrigatória
  const cpfBruto = soDigitos(corpo.cpf); // CPF opcional (necessário para a recuperação de senha)
  if (cpfBruto && !cpfValido(cpfBruto)) throw new ErroHttp(400, 'CPF inválido.'); // Se informado, precisa ser válido
  const senha = corpo.senha ? String(corpo.senha) : null; // Senha inicial opcional
  if (criando && senha && (senha.length < 8 || senha.length > 72)) throw new ErroHttp(400, 'A senha deve ter de 8 a 72 caracteres.'); // Regra de tamanho
  return { nome, email, turma, matricula, cpf: cpfBruto || null, senha }; // Devolve os dados limpos
} // Fecha lerDadosAluno

async function idDaTurma(conn, nome) { // Devolve o id da turma, criando-a se ainda não existir
  const [r] = await conn.execute('INSERT INTO turmas (nome) VALUES (?) ON DUPLICATE KEY UPDATE id = LAST_INSERT_ID(id)', [nome]); // Truque: insertId sempre traz o id (novo ou existente)
  return r.insertId; // Id da turma
} // Fecha idDaTurma

app.post('/api/professor/alunos', soProfessor, assincrono(async (req, res) => { // Botão "+ Novo aluno"
  const d = lerDadosAluno(req.body, true); // Valida o formulário
  const senhaProvisoria = d.senha ? null : crypto.randomBytes(6).toString('base64url'); // Se o professor não definiu senha, gera uma aleatória
  const hash = await bcrypt.hash(d.senha || senhaProvisoria, 10); // Criptografa a senha
  try { // Tenta cadastrar tudo em bloco
    const id = await comTransacao(async conn => { // Transação: usuário + aluno + documentos
      const turmaId = await idDaTurma(conn, d.turma); // Turma (criada se for nova)
      const [u] = await conn.execute( // Cria a conta de acesso
        "INSERT INTO usuarios (nome, email, cpf, senha_hash, perfil) VALUES (?, ?, ?, ?, 'aluno')", // Perfil fixo: aluno
        [d.nome, d.email, d.cpf, hash]); // Valores
      const [a] = await conn.execute('INSERT INTO alunos (usuario_id, turma_id, matricula) VALUES (?, ?, ?)', [u.insertId, turmaId, d.matricula]); // Cria o aluno
      await conn.execute("INSERT INTO documentos_aluno (aluno_id, tipo_id, situacao) SELECT ?, id, 'pendente' FROM documentos_tipos", [a.insertId]); // Todos os documentos começam pendentes
      return a.insertId; // Id do novo aluno
    }); // Fecha a transação
    res.status(201).json({ aluno: { id, nome: d.nome, email: d.email, turma: d.turma, matricula: d.matricula }, senhaProvisoria }); // Devolve o aluno (e a senha provisória, se gerada)
  } catch (e) { // Se algo falhar...
    throw erroDuplicado(e); // ...traduz erros de duplicidade
  } // Fecha try/catch
})); // Fecha POST /alunos

app.put('/api/professor/alunos/:id', soProfessor, assincrono(async (req, res) => { // Botão "Editar dados"
  const id = idDaRota(req.params.id); // Id do aluno na URL
  const d = lerDadosAluno(req.body, false); // Valida o formulário
  try { // Tenta atualizar em bloco
    await comTransacao(async conn => { // Transação: usuário + aluno
      const [linhas] = await conn.execute('SELECT usuario_id FROM alunos WHERE id = ?', [id]); // Descobre a conta do aluno
      if (!linhas[0]) throw new ErroHttp(404, 'Aluno não encontrado.'); // Não existe: erro 404
      const turmaId = await idDaTurma(conn, d.turma); // Turma (criada se for nova)
      await conn.execute('UPDATE usuarios SET nome = ?, email = ? WHERE id = ?', [d.nome, d.email, linhas[0].usuario_id]); // Atualiza nome e e-mail
      if (d.cpf) await conn.execute('UPDATE usuarios SET cpf = ? WHERE id = ?', [d.cpf, linhas[0].usuario_id]); // CPF só muda se foi informado
      await conn.execute('UPDATE alunos SET turma_id = ?, matricula = ? WHERE id = ?', [turmaId, d.matricula, id]); // Atualiza turma e matrícula
    }); // Fecha a transação
  } catch (e) { // Se algo falhar...
    throw erroDuplicado(e); // ...traduz erros de duplicidade
  } // Fecha try/catch
  res.json({ aluno: { id, nome: d.nome, email: d.email, turma: d.turma, matricula: d.matricula } }); // Devolve os dados atualizados
})); // Fecha PUT /alunos/:id

app.delete('/api/professor/alunos/:id', soProfessor, assincrono(async (req, res) => { // Botão "Excluir"
  const id = idDaRota(req.params.id); // Id do aluno na URL
  const [linhas] = await pool.execute('SELECT usuario_id FROM alunos WHERE id = ?', [id]); // Descobre a conta do aluno
  if (!linhas[0]) throw new ErroHttp(404, 'Aluno não encontrado.'); // Não existe: erro 404
  await pool.execute('DELETE FROM usuarios WHERE id = ?', [linhas[0].usuario_id]); // Apaga o usuário (o banco apaga em cascata notas, faltas e documentos)
  res.json({ mensagem: 'Aluno excluído.' }); // Confirma
})); // Fecha DELETE /alunos/:id

async function exigirAlunoEAno(idTexto, anoTexto) { // Confere se o aluno e o ano letivo existem
  const id = idDaRota(idTexto); // Valida o id do aluno
  const ano = Number(anoTexto); // Converte o ano
  if (!Number.isInteger(ano)) throw new ErroHttp(400, 'Ano inválido.'); // Ano precisa ser inteiro
  const [a] = await pool.execute('SELECT id FROM alunos WHERE id = ?', [id]); // Procura o aluno
  if (!a[0]) throw new ErroHttp(404, 'Aluno não encontrado.'); // Aluno inexistente
  const [y] = await pool.execute('SELECT ano FROM anos_letivos WHERE ano = ?', [ano]); // Procura o ano letivo
  if (!y[0]) throw new ErroHttp(404, 'Ano letivo não cadastrado.'); // Ano inexistente
  return { id, ano }; // Devolve os valores validados
} // Fecha exigirAlunoEAno

app.get('/api/professor/alunos/:id/lancamentos/:ano', soProfessor, assincrono(async (req, res) => { // Carrega o editor do aluno
  const { id, ano } = await exigirAlunoEAno(req.params.id, req.params.ano); // Valida aluno e ano
  const discs = await disciplinas(); // Lista de disciplinas
  const lanc = (await buscarLancamentos(id, ano))[ano]; // Notas e faltas daquele ano
  res.json({ // Resposta no formato que o painel usa
    bim: lanc.bim, // Notas bimestrais
    notas: lanc.notas, // Notas mensais
    faltas: lanc.faltas, // Faltas mensais
    documentos: await buscarDocumentos(id), // Documentos do aluno
    aulasPorMes: Object.fromEntries(discs.map(d => [d.nome, d.aulas])) // Limite de faltas por disciplina
  }); // Fecha res.json
})); // Fecha GET lançamentos

function lerGrade(grade, rotulo, discs, tamanho, validar) { // Valida uma grade { disciplina: [valores] } e devolve linhas [disc_id, posição, valor]
  if (!grade || typeof grade !== 'object') throw new ErroHttp(400, `Campo "${rotulo}" ausente.`); // A grade precisa existir
  const linhas = []; // Resultado
  for (const d of discs) { // Para cada disciplina...
    const lista = grade[d.nome]; // ...pega a lista de valores
    if (!Array.isArray(lista) || lista.length !== tamanho) throw new ErroHttp(400, `"${rotulo}" de ${d.nome} deve ter ${tamanho} posições.`); // Tamanho errado
    lista.forEach((v, i) => { // Para cada posição (bimestre ou mês)...
      if (v === null || v === undefined || v === '') return; // ...vazio = não lançado (ignora)
      const ok = validar(Number(v), d); // ...valida o valor
      if (ok === null) throw new ErroHttp(400, `Valor inválido em "${rotulo}" (${d.nome}, posição ${i + 1}).`); // Valor fora das regras
      linhas.push([d.id, i, ok]); // Guarda a linha válida
    }); // Fecha o forEach
  } // Fecha o laço de disciplinas
  return linhas; // Devolve as linhas válidas
} // Fecha lerGrade

const validarNota = n => (Number.isFinite(n) && n >= 0 && n <= 10 ? Math.round(n * 10) / 10 : null); // Nota de 0 a 10 com uma casa decimal
const validarFalta = (n, d) => (Number.isInteger(n) && n >= 0 && n <= d.aulas ? n : null); // Falta inteira de 0 até o total de aulas do mês

app.put('/api/professor/alunos/:id/lancamentos/:ano', soProfessor, assincrono(async (req, res) => { // Botão "Salvar alterações"
  const { id, ano } = await exigirAlunoEAno(req.params.id, req.params.ano); // Valida aluno e ano
  const discs = await disciplinas(); // Lista de disciplinas
  const bim = lerGrade(req.body.bim, 'bim', discs, N_BIM, validarNota); // Valida as notas bimestrais
  const notas = lerGrade(req.body.notas, 'notas', discs, MESES_LETIVOS.length, validarNota); // Valida as notas mensais
  const faltas = lerGrade(req.body.faltas, 'faltas', discs, MESES_LETIVOS.length, validarFalta); // Valida as faltas mensais
  const docs = req.body.documentos; // Documentos (opcional)
  if (docs !== undefined) { // Se vieram documentos, valida cada um
    if (!Array.isArray(docs)) throw new ErroHttp(400, 'Campo "documentos" inválido.'); // Precisa ser lista
    docs.forEach(x => { // Para cada documento...
      if (!x || !TIPOS_SITUACAO.includes(x.situacao)) throw new ErroHttp(400, 'Situação de documento inválida.'); // ...situação permitida
      if (x.data && (!DATA_RE.test(x.data) || Number.isNaN(Date.parse(x.data)))) throw new ErroHttp(400, 'Data de documento inválida.'); // ...data válida
    }); // Fecha o forEach dos documentos
  } // Fecha o if dos documentos
  await comTransacao(async conn => { // Tudo é gravado junto, ou nada é gravado
    await conn.query('DELETE FROM notas_bimestrais WHERE aluno_id = ? AND ano = ?', [id, ano]); // Limpa as notas bimestrais do ano
    if (bim.length) await conn.query('INSERT INTO notas_bimestrais (aluno_id, ano, disciplina_id, bimestre, nota) VALUES ?', [bim.map(([d, i, v]) => [id, ano, d, i + 1, v])]); // Regrava só as preenchidas (bimestre = posição + 1)
    await conn.query('DELETE FROM notas_mensais WHERE aluno_id = ? AND ano = ?', [id, ano]); // Limpa as notas mensais do ano
    if (notas.length) await conn.query('INSERT INTO notas_mensais (aluno_id, ano, disciplina_id, mes, nota) VALUES ?', [notas.map(([d, i, v]) => [id, ano, d, MESES_LETIVOS[i], v])]); // Regrava convertendo posição em número do mês
    await conn.query('DELETE FROM faltas_mensais WHERE aluno_id = ? AND ano = ?', [id, ano]); // Limpa as faltas do ano
    if (faltas.length) await conn.query('INSERT INTO faltas_mensais (aluno_id, ano, disciplina_id, mes, quantidade) VALUES ?', [faltas.map(([d, i, v]) => [id, ano, d, MESES_LETIVOS[i], v])]); // Regrava as faltas preenchidas
    if (docs !== undefined) { // Atualiza documentos apenas se foram enviados
      const [tipos] = await conn.query('SELECT id, nome FROM documentos_tipos'); // Tipos de documento cadastrados
      const idPorNome = new Map(tipos.map(t => [t.nome, t.id])); // Mapa nome -> id
      const linhasDoc = docs.map(x => { // Monta as linhas a gravar
        const tipoId = idPorNome.get(x.nome); // Descobre o tipo pelo nome
        if (!tipoId) throw new ErroHttp(400, `Documento desconhecido: ${x.nome}`); // Nome inexistente
        const data = x.situacao === 'pendente' ? null : (x.data || hojeISO()); // Pendente = sem data; senão usa a data ou a de hoje
        return [id, tipoId, x.situacao, data]; // Linha pronta
      }); // Fecha o map
      if (linhasDoc.length) await conn.query( // Grava (ou atualiza) todos os documentos
        'INSERT INTO documentos_aluno (aluno_id, tipo_id, situacao, data_entrega) VALUES ? ' + // Insere
        'ON DUPLICATE KEY UPDATE situacao = VALUES(situacao), data_entrega = VALUES(data_entrega)', [linhasDoc]); // Se já existir, atualiza
    } // Fecha o if dos documentos
  }); // Fecha a transação
  res.json({ mensagem: 'Lançamentos salvos. Já aparecem no perfil do aluno.' }); // Confirma
})); // Fecha PUT lançamentos

// =====================================================================
// 10. ROTAS DA SECRETARIA (secretaria.html)
// =====================================================================
app.post('/api/secretaria/solicitacoes', limiteSecretaria, assincrono(async (req, res) => { // Formulário "Solicitar documento"
  const nome = exigirTexto(req.body.nome, 'nome completo', 120); // Nome obrigatório
  const email = exigirTexto(req.body.email, 'e-mail', 150); // E-mail obrigatório
  if (!EMAIL_RE.test(email)) throw new ErroHttp(400, 'Informe um e-mail válido.'); // Formato do e-mail
  const matricula = textoOpcional(req.body.matricula, 'matrícula', 30); // Matrícula opcional
  const documento = exigirTexto(req.body.documento, 'documento desejado', 60); // Documento obrigatório
  if (!DOCUMENTOS_SECRETARIA.includes(documento)) throw new ErroHttp(400, 'Documento desejado inválido.'); // Só aceita as opções do formulário
  const detalhes = textoOpcional(req.body.detalhes, 'detalhes', 1000); // Detalhes opcionais
  const protocolo = `EDU-${new Date().getFullYear()}-${crypto.randomBytes(4).toString('hex').toUpperCase()}`; // Protocolo, ex.: EDU-2026-A1B2C3D4
  await pool.execute( // Grava a solicitação
    'INSERT INTO solicitacoes (protocolo, nome, email, matricula, documento, detalhes) VALUES (?, ?, ?, ?, ?, ?)', // Comando preparado
    [protocolo, nome, email, matricula, documento, detalhes]); // Valores
  res.status(201).json({ protocolo, mensagem: 'Solicitação registrada.' }); // Devolve o protocolo ao solicitante
})); // Fecha POST solicitações

app.get('/api/secretaria/solicitacoes/:protocolo', limiteSecretaria, assincrono(async (req, res) => { // Consulta de andamento pelo protocolo
  const protocolo = String(req.params.protocolo || '').toUpperCase(); // Protocolo informado
  if (!/^EDU-\d{4}-[A-F0-9]{8}$/.test(protocolo)) throw new ErroHttp(400, 'Protocolo inválido.'); // Formato esperado
  const [linhas] = await pool.execute('SELECT protocolo, documento, status, criado_em FROM solicitacoes WHERE protocolo = ?', [protocolo]); // Busca (sem dados pessoais)
  if (!linhas[0]) throw new ErroHttp(404, 'Protocolo não encontrado.'); // Não existe: erro 404
  res.json(linhas[0]); // Devolve o andamento
})); // Fecha GET solicitação

// =====================================================================
// 11. ROTA NÃO ENCONTRADA E TRATADOR DE ERROS
// =====================================================================
app.use((req, res) => res.status(404).json({ erro: 'Rota não encontrada.' })); // Qualquer endereço desconhecido cai aqui

app.use((err, req, res, next) => { // Tratador central de erros (precisa ter 4 parâmetros)
  if (err instanceof ErroHttp) return res.status(err.status).json({ erro: err.message }); // Erros nossos: devolve a mensagem
  if (err.status === 403) return res.status(403).json({ erro: err.message }); // Bloqueio do CORS
  if (err.type === 'entity.parse.failed') return res.status(400).json({ erro: 'JSON inválido.' }); // Corpo mal formado
  if (err.type === 'entity.too.large') return res.status(413).json({ erro: 'Conteúdo grande demais.' }); // Corpo acima do limite
  if (err.code === 'ER_DUP_ENTRY') return res.status(409).json({ erro: 'Registro duplicado.' }); // Duplicidade não tratada antes
  console.error('Erro interno:', err); // Registra o erro real no log (não vai para o usuário)
  return res.status(500).json({ erro: 'Erro interno do servidor.' }); // Mensagem genérica ao usuário
}); // Fecha o tratador de erros

// =====================================================================
// 12. INICIALIZAÇÃO
// =====================================================================
const servidor = app.listen(PORT, () => { // Liga o servidor na porta definida
  console.log(`API EduConnect ouvindo na porta ${PORT}`); // Mensagem de confirmação
  pool.query('SELECT 1') // Testa a conexão com o banco assim que o servidor sobe
    .then(() => console.log('Conexão com o banco OK.')) // Sucesso
    .catch(e => console.error('Falha ao conectar ao banco:', e.code || e.message)); // Falha (a API continua no ar)
}); // Fecha o listen

process.on('SIGTERM', () => { // O Render envia SIGTERM ao reiniciar/desligar o serviço
  servidor.close(() => pool.end().then(() => process.exit(0))); // Para de aceitar requisições, fecha o banco e sai
}); // Fecha o tratador do SIGTERM
