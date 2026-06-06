package login;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.PreparedStatement;
import java.sql.ResultSet;
import java.sql.SQLException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.nio.charset.StandardCharsets;

/**
 * Melhorias implementadas:
 * <ul>
 *   <li>Eliminação de SQL Injection via PreparedStatement com parâmetros.</li>
 *   <li>Credenciais externalizadas para variáveis de ambiente.</li>
 *   <li>Fechamento automático de recursos com try-with-resources.</li>
 *   <li>Exceções registradas em log (System.err) ao invés de silenciadas.</li>
 *   <li>Hash SHA-256 aplicado à senha antes da comparação.</li>
 *   <li>Encapsulamento adequado dos atributos (private + getters).</li>
 *   <li>Separação de responsabilidades: conectarBD lança SQLException.</li>
 *   <li>JavaDoc completo em todos os métodos públicos.</li>
 * </ul>
 */
public class UserRefatorado {

    /** Nome do usuário autenticado; null enquanto não autenticado. */
    private String nome;

    /** Resultado da última verificação de credenciais. */
    private boolean autenticado;

    // Constantes de configuração

    /**
     * Nome da variável de ambiente que contém a URL de conexão JDBC.
     * Exemplo: jdbc:mysql://127.0.0.1:3306/meubanco
     */
    private static final String ENV_DB_URL  = "DB_URL";

    /**
     * Nome da variável de ambiente que contém o usuário do banco de dados.
     */
    private static final String ENV_DB_USER = "DB_USER";

    /**
     * Nome da variável de ambiente que contém a senha do banco de dados.
     */
    private static final String ENV_DB_PASS = "DB_PASSWORD";

    // Construtor

    /**
     * Inicializa o objeto com estado padrão (não autenticado, nome nulo).
     */
    public UserRefatorado() {
        this.nome = null;
        this.autenticado = false;
    }

    // Métodos de negócio

    /**
     * Verifica se as credenciais fornecidas correspondem a um usuário cadastrado.
     *
     * <p>A senha é hasheada com SHA-256 antes da consulta. A query utiliza
     * {@link PreparedStatement} com parâmetros posicionais, eliminando qualquer
     * possibilidade de SQL Injection.</p>
     *
     * <p>Todos os recursos JDBC (Connection, PreparedStatement, ResultSet) são
     * fechados automaticamente ao final do bloco try-with-resources, independente
     * de sucesso ou exceção.</p>
     *
     * @param login Login informado pelo usuário.
     * @param senha Senha em texto puro informada pelo usuário.
     * @return {@code true} se as credenciais são válidas; {@code false} caso contrário.
     */
    public boolean verificarUsuario(String login, String senha) {
        // Validação de entrada básica — evita chamadas desnecessárias ao banco
        if (login == null || login.isBlank() || senha == null || senha.isBlank()) {
            System.err.println("[AVISO] Login ou senha fornecidos são nulos/vazios.");
            return false;
        }

        // Cálculo do hash da senha antes de enviar ao banco
        String senhaHash = hashSHA256(senha);
        if (senhaHash == null) {
            System.err.println("[ERRO] Não foi possível calcular o hash da senha.");
            return false;
        }

        // Query parametrizada — imune a SQL Injection
        String sql = "SELECT nome FROM usuarios WHERE login = ? AND senha_hash = ?";

        // try-with-resources: Connection e PreparedStatement fechados automaticamente
        try (Connection conn = conectarBD();
             PreparedStatement ps = conn.prepareStatement(sql)) {

            // Define os parâmetros pelo índice posicional — nenhuma concatenação de strings
            ps.setString(1, login);
            ps.setString(2, senhaHash);

            // Executa a query com parâmetros seguros
            try (ResultSet rs = ps.executeQuery()) {
                if (rs.next()) {
                    this.autenticado = true;
                    this.nome = rs.getString("nome");
                    System.out.println("[INFO] Usuário autenticado com sucesso: " + this.nome);
                } else {
                    System.out.println("[INFO] Credenciais inválidas para login: " + login);
                }
            }

        } catch (SQLException e) {
            // Exceção registrada com detalhes para diagnóstico — não silenciada
            System.err.println("[ERRO] Falha na verificação de usuário: " + e.getMessage());
            System.err.println("[ERRO] SQLState: " + e.getSQLState() + " | Código: " + e.getErrorCode());
        }

        return this.autenticado;
    }

    // Métodos auxiliares privados

    /**
     * Abre e retorna uma conexão com o banco de dados a partir das variáveis
     * de ambiente configuradas ({@value #ENV_DB_URL}, {@value #ENV_DB_USER},
     * {@value #ENV_DB_PASS}).
     *
     * <p>Ao contrário da versão original, este método declara {@link SQLException}
     * na assinatura, tornando falhas de conexão explícitas para o chamador em vez
     * de retornar {@code null} silenciosamente.</p>
     *
     * @return Conexão JDBC ativa.
     * @throws SQLException se a conexão não puder ser estabelecida.
     * @throws IllegalStateException se as variáveis de ambiente não estiverem configuradas.
     */
    private Connection conectarBD() throws SQLException {
        String url  = System.getenv(ENV_DB_URL);
        String user = System.getenv(ENV_DB_USER);
        String pass = System.getenv(ENV_DB_PASS);

        // Verifica se as variáveis de ambiente estão definidas
        if (url == null || user == null || pass == null) {
            throw new IllegalStateException(
                "Variáveis de ambiente de banco de dados não configuradas: "
                + ENV_DB_URL + ", " + ENV_DB_USER + ", " + ENV_DB_PASS
            );
        }

        // Usa as credenciais externas — nunca hardcoded no código-fonte
        return DriverManager.getConnection(url, user, pass);
    }

    /**
     * Calcula o hash SHA-256 de uma string e retorna sua representação hexadecimal.
     *
     * <p>Para uso em produção com senhas de usuários, prefira BCrypt ou Argon2
     * (com salt aleatório), que são resistentes a ataques de força bruta por GPU.</p>
     *
     * @param texto Texto a ser hasheado.
     * @return Hash SHA-256 em hexadecimal minúsculo, ou {@code null} em caso de erro.
     */
    private String hashSHA256(String texto) {
        try {
            MessageDigest digest = MessageDigest.getInstance("SHA-256");
            byte[] bytes = digest.digest(texto.getBytes(StandardCharsets.UTF_8));

            // Converte bytes para hexadecimal
            StringBuilder sb = new StringBuilder();
            for (byte b : bytes) {
                sb.append(String.format("%02x", b));
            }
            return sb.toString();

        } catch (NoSuchAlgorithmException e) {
            System.err.println("[ERRO] Algoritmo SHA-256 não disponível: " + e.getMessage());
            return null;
        }
    }

    // Getters — encapsulamento adequado (sem setters externos)

    /**
     * Retorna o nome do usuário autenticado.
     *
     * @return Nome do usuário, ou {@code null} se não autenticado.
     */
    public String getNome() {
        return nome;
    }

    /**
     * Indica se o último processo de autenticação foi bem-sucedido.
     *
     * @return {@code true} se autenticado; {@code false} caso contrário.
     */
    public boolean isAutenticado() {
        return autenticado;
    }

    // Método principal — demonstração de uso

    /**
     * Demonstra o uso da classe. Para executar, configure as variáveis de ambiente:
     * <pre>
     *   export DB_URL="jdbc:mysql://localhost:3306/meubanco"
     *   export DB_USER="usuario_seguro"
     *   export DB_PASSWORD="senha_segura"
     * </pre>
     *
     * @param args Argumentos de linha de comando (não utilizados).
     */
    public static void main(String[] args) {
        UserRefatorado user = new UserRefatorado();

        // Teste com credenciais fictícias
        boolean autenticado = user.verificarUsuario("joao.silva", "minhasenha123");

        if (autenticado) {
            System.out.println("Bem-vindo, " + user.getNome() + "!");
        } else {
            System.out.println("Acesso negado.");
        }
    }
}
