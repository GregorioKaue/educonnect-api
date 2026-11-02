'use strict'; // Ativa o modo estrito do JavaScript
// Script de uso único: grava hashes bcrypt REAIS para os dois usuários de demonstração do educonnect.sql.
// Motivo: os hashes do SQL são apenas ilustrativos e não correspondem a "123456" / "prof123".
// Uso (na sua máquina, com o .env preenchido):  npm run seed-senhas
require('dotenv').config(); // Lê o .env com os dados do banco
const mysql = require('mysql2/promise'); // Driver do MariaDB/MySQL
const bcrypt = require('bcryptjs'); // Gerador de hash de senha

const CONTAS = [ // Contas de demonstração e suas senhas
  { email: 'aluno@escola.com.br', senha: '123456' }, // Aluna Maria Souza
  { email: 'professor@educonnect.com', senha: 'prof123' } // Professor de demonstração
]; // Fecha a lista de contas

(async () => { // Função assíncrona executada imediatamente
  const conn = await mysql.createConnection({ // Abre uma conexão única com o banco
    host: process.env.DB_HOST, // Servidor
    port: Number(process.env.DB_PORT || 3306), // Porta
    user: process.env.DB_USER, // Usuário
    password: process.env.DB_PASSWORD, // Senha
    database: process.env.DB_NAME // Banco
  }); // Fecha a configuração da conexão
  for (const c of CONTAS) { // Para cada conta de demonstração...
    const hash = await bcrypt.hash(c.senha, 10); // ...gera o hash bcrypt da senha
    const [r] = await conn.execute('UPDATE usuarios SET senha_hash = ? WHERE email = ?', [hash, c.email]); // ...grava no banco
    console.log(`${c.email}: ${r.affectedRows ? 'senha atualizada' : 'usuário NÃO encontrado'}`); // ...informa o resultado
  } // Fecha o laço
  await conn.end(); // Fecha a conexão
})().catch(e => { console.error('Erro:', e.message); process.exit(1); }); // Mostra qualquer erro e sai com falha
