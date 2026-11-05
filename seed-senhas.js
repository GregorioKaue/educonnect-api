'use strict'; // Ativa o modo estrito do JavaScript
// Script de uso único: cria (ou atualiza) as duas contas de demonstração com hash bcrypt REAL.
// Uso (na sua máquina, com o .env preenchido e o schema.sql já importado):  npm run seed-senhas
require('dotenv').config(); // Lê o .env com os dados do banco
const mysql = require('mysql2/promise'); // Driver do MariaDB/MySQL
const bcrypt = require('bcryptjs'); // Gerador de hash de senha

const DOCS = ['Certidão de nascimento', 'RG ou CPF do aluno', 'Comprovante de residência', 'Histórico escolar anterior', // Documentos criados para o aluno de demonstração
  'Cartão de vacina', 'Foto 3x4', 'Declaração de transferência', 'Termo de autorização de imagem']; // (iguais aos criados pela API)

(async () => { // Função assíncrona executada imediatamente
  const conn = await mysql.createConnection({ // Abre uma conexão única com o banco
    host: process.env.DB_HOST, // Servidor
    port: Number(process.env.DB_PORT || 3306), // Porta
    user: process.env.DB_USER, // Usuário
    password: process.env.DB_PASSWORD, // Senha
    database: process.env.DB_NAME // Banco
  }); // Fecha a configuração da conexão

  const hashAluno = await bcrypt.hash('12345678', 10); // Hash da senha do aluno (mínimo de 8 caracteres, como exige a API)
  const [[existe]] = await conn.query('SELECT id FROM alunos WHERE email = ?', ['aluno@escola.com.br']); // Procura o aluno de demonstração
  let alunoId = existe && existe.id; // Guarda o id se ele já existir
  if (alunoId) { // Se já existe...
    await conn.execute('UPDATE alunos SET senha_hash = ? WHERE id = ?', [hashAluno, alunoId]); // ...apenas atualiza a senha
  } else { // Se não existe...
    const [r] = await conn.execute( // ...cria o aluno (sem CPF)
      'INSERT INTO alunos (nome, email, matricula, turma, senha_hash) VALUES (?,?,?,?,?)',
      ['Maria Souza', 'aluno@escola.com.br', '2026000001', '7º A', hashAluno]);
    alunoId = r.insertId; // Guarda o id novo
  } // Fecha o if/else
  await conn.query('INSERT IGNORE INTO documentos (aluno_id, nome) VALUES ?', [DOCS.map(n => [alunoId, n])]); // Garante os documentos pendentes do aluno
  console.log('aluno@escola.com.br: pronto (senha 12345678)'); // Informa o resultado

  const hashProf = await bcrypt.hash('prof12345', 10); // Hash da senha do professor
  await conn.execute( // Cria o professor ou atualiza a senha se o e-mail já existir
    `INSERT INTO professores (nome, email, disciplina, senha_hash) VALUES (?,?,?,?)
     ON DUPLICATE KEY UPDATE senha_hash = VALUES(senha_hash)`,
    ['Professor Demonstração', 'professor@educonnect.com', 'Matemática', hashProf]);
  console.log('professor@educonnect.com: pronto (senha prof12345)'); // Informa o resultado

  await conn.end(); // Fecha a conexão
})().catch(e => { console.error('Erro:', e.message); process.exit(1); }); // Mostra qualquer erro e sai com falha
