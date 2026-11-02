// Cliente da API para o frontend (GitHub Pages). Salve em  pages/api.js  e inclua nas páginas com:
//   <script src="api.js"></script>   (antes do <script> principal de cada página)

const API_URL = "https://SEU-SERVICO.onrender.com"; // Endereço da API no Render (sem barra no final)

// Função base: faz a chamada HTTP, envia o token e trata os erros de forma única.
async function api(caminho, { metodo = "GET", corpo } = {}) { // Recebe o caminho, o método e o corpo (opcional)
  const token = sessionStorage.getItem("token"); // Lê o token de login guardado na sessão do navegador
  const cabecalhos = { "Content-Type": "application/json" }; // Todo envio e resposta é JSON
  if (token) cabecalhos.Authorization = "Bearer " + token; // Se houver login, anexa o token ao cabeçalho
  let resposta; // Guardará a resposta do servidor
  try { // Tenta se comunicar com a API
    resposta = await fetch(API_URL + caminho, { // Faz a requisição
      method: metodo, // GET, POST, PUT ou DELETE
      headers: cabecalhos, // Cabeçalhos montados acima
      body: corpo !== undefined ? JSON.stringify(corpo) : undefined // Converte o corpo em JSON (se existir)
    }); // Fecha o fetch
  } catch (e) { // Falha de rede (API acordando, sem internet, CORS bloqueado)
    throw new Error("Não foi possível conectar ao servidor. Se o serviço estava inativo, aguarde cerca de 1 minuto e tente de novo."); // Mensagem amigável
  } // Fecha try/catch
  const dados = await resposta.json().catch(() => ({})); // Lê o JSON da resposta (ou objeto vazio se não houver)
  if (resposta.status === 401 && token) { // Token vencido ou inválido
    const eProfessor = !!sessionStorage.getItem("professorLogado"); // Descobre qual login usar
    sessionStorage.clear(); // Apaga a sessão antiga
    window.location.href = eProfessor ? "loginProf.html" : "login.html"; // Volta para a tela de login correta
  } // Fecha o if do 401
  if (!resposta.ok) throw new Error(dados.erro || "Erro inesperado."); // Qualquer erro HTTP vira exceção com a mensagem da API
  return dados; // Devolve os dados da resposta
} // Fecha api()

// ---------- Atalhos por assunto (um por rota da API) ----------
const EduAPI = { // Objeto que agrupa todas as chamadas
  // Autenticação
  loginAluno: (email, senha) => api("/api/auth/login/aluno", { metodo: "POST", corpo: { email, senha } }), // login.html
  loginProfessor: (email, senha) => api("/api/auth/login/professor", { metodo: "POST", corpo: { email, senha } }), // loginProf.html
  esqueciSenha: (email, cpf) => api("/api/auth/esqueci-senha", { metodo: "POST", corpo: { email, cpf } }), // esqueci-senha.html
  redefinirSenha: (token, novaSenha) => api("/api/auth/redefinir-senha", { metodo: "POST", corpo: { token, novaSenha } }), // página de redefinição

  // Aluno
  perfil: () => api("/api/aluno/perfil"), // Cabeçalho do perfil (inclui foto)
  salvarFoto: foto => api("/api/aluno/foto", { metodo: "PUT", corpo: { foto } }), // Foto em data-URL (ou null para remover)
  desempenho: () => api("/api/aluno/desempenho"), // Notas, faltas, bimestres e documentos

  // Professor
  anos: () => api("/api/professor/anos"), // Lista de anos letivos
  novoAno: ano => api("/api/professor/anos", { metodo: "POST", corpo: { ano } }), // Botão "+ Ano"
  alunos: () => api("/api/professor/alunos"), // Lista de alunos
  novoAluno: dados => api("/api/professor/alunos", { metodo: "POST", corpo: dados }), // Botão "+ Novo aluno"
  editarAluno: (id, dados) => api("/api/professor/alunos/" + id, { metodo: "PUT", corpo: dados }), // Botão "Editar dados"
  excluirAluno: id => api("/api/professor/alunos/" + id, { metodo: "DELETE" }), // Botão "Excluir"
  lancamentos: (id, ano) => api("/api/professor/alunos/" + id + "/lancamentos/" + ano), // Carrega o editor
  salvarLancamentos: (id, ano, corpo) => api("/api/professor/alunos/" + id + "/lancamentos/" + ano, { metodo: "PUT", corpo }), // Botão "Salvar alterações"

  // Secretaria
  solicitar: dados => api("/api/secretaria/solicitacoes", { metodo: "POST", corpo: dados }), // Formulário da secretaria
  consultarProtocolo: protocolo => api("/api/secretaria/solicitacoes/" + encodeURIComponent(protocolo)) // Andamento do pedido
}; // Fecha EduAPI
