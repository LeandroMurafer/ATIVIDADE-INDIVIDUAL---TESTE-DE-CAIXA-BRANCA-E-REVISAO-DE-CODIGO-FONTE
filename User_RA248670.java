package login;

import java.sql.Connection;
import java.sql.DriverManager;
import java.sql.ResultSet;
import java.sql.Statement;

/**
 * Classe User — versão original reproduzida com comentários explicativos.
 *
 *Este código possui vulnerabilidades graves identificadas na análise
 */
public class User {

    /**
     * Estabelece e retorna uma conexão com o banco de dados MySQL.
     *
     * PROBLEMA 1 — Credenciais hardcoded:
     * O usuário ("lopes") e a senha ("123") estão embutidos diretamente
     * na URL de conexão. Qualquer pessoa com acesso ao código-fonte
     * tem acesso às credenciais do banco de dados.
     *
     * PROBLEMA 2 — Exceção silenciada:
     * O bloco catch captura todas as exceções sem registrá-las.
     * Se o driver não for encontrado ou a conexão falhar, o método
     * retorna null sem nenhuma mensagem de erro.
     *
     * PROBLEMA 3 — Retorno null:
     * Retornar null em caso de falha obriga o chamador a verificar
     * null antes de usar a conexão, o que não é feito no código original,
     * causando risco de NullPointerException.
     *
     * @return Connection com o banco, ou null em caso de falha.
     */
    public Connection conectarBD() {
        Connection conn = null;
        try {
            // Carrega o driver JDBC do MySQL (abordagem obsoleta — preferir DataSource)
            Class.forName("com.mysql.Driver.Manager").newInstance();

            // URL com credenciais expostas — vulnerabilidade de segurança
            String url = "jdbc:mysql://127.0.0.1/test?user=lopes&password=123";

            // Abre a conexão
            conn = DriverManager.getConnection(url);

        } catch (Exception e) {
            // PROBLEMA: exceção completamente ignorada — nenhum log, nenhum aviso
        }
        return conn; // pode retornar null sem aviso
    }

    //Atributo público sem encapsulamento — expõe estado interno diretamente
    public String nome = "";

    // Atributo público inicializado como false — valor padrão de retorno
    public boolean result = false;

    /**
     * Verifica se o login e senha fornecidos correspondem a um usuário cadastrado.
     *
     * VULNERABILIDADE CRÍTICA — SQL Injection:
     * Os parâmetros "login" e "senha" são concatenados diretamente na query SQL.
     * Um atacante pode inserir ' OR '1'='1 como login para obter acesso irrestrito.
     *
     * Exemplo de ataque:
     *   login = " ' OR '1'='1 "
     *   senha = qualquer coisa
     *   SQL gerada: SELECT nome FROM usuarios WHERE login = '' OR '1'='1' AND senha = '...'
     *   Resultado: retorna todos os usuários — autenticação bypassada.
     *
     * PROBLEMA — Recursos não fechados:
     * Statement e ResultSet não são fechados após o uso, causando vazamento de recursos.
     *
     * PROBLEMA — Senha em texto puro:
     * A senha é comparada diretamente sem hash, expondo credenciais no banco de dados.
     *
     * @param login  Login do usuário (não sanitizado — vulnerável a SQL Injection)
     * @param senha  Senha do usuário em texto puro (sem hash)
     * @return true se usuário encontrado, false caso contrário ou em caso de erro
     */
    public boolean verificarUsuario(String login, String senha) {

        // Declaração da variável SQL (inicializada como string vazia)
        String sql = "";

        // Obtém conexão com o banco (pode retornar null sem aviso)
        Connection conn = conectarBD();

        // INSTRUÇÃO SQL — construída por concatenação: vulnerável a SQL Injection
        sql += "select nome from usuarios ";
        sql += "where login = " + "'" + login + "'";   // entrada direta do usuário
        sql += " and senha = " + "'" + senha + "'";    // entrada direta do usuário

        try {
            // Cria Statement (pode lançar NullPointerException se conn == null)
            Statement st = conn.createStatement();

            // Executa a query vulnerável
            ResultSet rs = st.executeQuery(sql);

            // Verifica se há resultado
            if (rs.next()) {
                result = true;             // usuário encontrado
                nome = rs.getString("nome"); // obtém nome do usuário
            }
            // PROBLEM: Statement e ResultSet não são fechados (st.close(), rs.close())

        } catch (Exception e) {
            // PROBLEMA: exceção completamente ignorada — qualquer erro passa em silêncio
        }

        return result; // retorna false em caso de erro ou usuário não encontrado
    }

} // fim da class
