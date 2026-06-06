# ATIVIDADE-INDIVIDUAL---TESTE-DE-CAIXA-BRANCA-E-REVISAO-DE-CODIGO-FONTE
Atividade individual.


# Teste de Caixa Branca — Classe `User` (Login com MySQL)

## 1. Introdução

Este relatório apresenta a análise técnica completa da classe `User`, escrita em Java, cujo objetivo é realizar a autenticação de usuários consultando um banco de dados MySQL. A atividade aplica a técnica de **teste de caixa branca (estrutural)**, examinando o código-fonte internamente para identificar falhas, vulnerabilidades e oportunidades de melhoria, bem como para modelar o fluxo de execução por meio de grafo de fluxo e cálculo da complexidade ciclomática.

O código original implementa dois métodos principais:
- `conectarBD()` — abre e retorna uma conexão JDBC com o banco de dados.
- `verificarUsuario(String login, String senha)` — executa uma consulta SQL para verificar as credenciais fornecidas.

---

## 2. Análise Estática do Código

### 2.1 Documentação
O código **não possui nenhum comentário explicativo ou JavaDoc**. Não há descrição de classe, de métodos, dos parâmetros recebidos nem dos valores retornados. Para um componente de autenticação — crítico para a segurança da aplicação — a ausência de documentação representa um risco significativo de manutenção.

### 2.2 Nomenclatura
A nomenclatura segue parcialmente as convenções Java (camelCase para atributos e métodos). Porém:
- O atributo `nome` não indica a que entidade pertence.
- A variável `st` (Statement) e `rs` (ResultSet) são abreviações que dificultam a leitura.
- Os nomes `result` e `sql` são genéricos e pouco descritivos em contextos maiores.

### 2.3 Legibilidade
- A montagem da SQL por concatenação de strings em múltiplas linhas (`+=`) dificulta a leitura e é propensa a erros.
- O bloco `catch` está vazio (`{ }`), silenciando exceções sem qualquer registro ou tratamento.
- Credenciais de banco de dados (usuário `lopes` e senha `123`) estão **embutidas diretamente na string de URL** (hardcoded).

### 2.4 Tratamento de Exceções
O `catch (Exception e) { }` no método `verificarUsuario` captura todas as exceções silenciosamente, sem:
- Registrar o erro em log.
- Notificar o chamador sobre a falha.
- Diferenciar erros de conexão de erros de lógica.

Isso torna o diagnóstico de falhas em produção praticamente impossível.

### 2.5 Segurança — Vulnerabilidade Crítica: SQL Injection

```java
sql += "where login = " + "'" + login + "'";
sql += " and senha = " + "'" + senha + "'";
```

Este é o problema mais grave do código. A construção da SQL por **concatenação direta de entrada do usuário** torna a aplicação **completamente vulnerável a SQL Injection**. Um atacante pode inserir como `login`:

```
' OR '1'='1
```

Fazendo a query retornar todos os usuários e autenticar sem credenciais válidas. A correção mandatória é o uso de `PreparedStatement` com parâmetros.

### 2.6 Credenciais Hardcoded

```java
String url = "jdbc:mysql://127.0.0.1/test?user=lopes&password=123";
```

Credenciais expostas no código-fonte são um risco severo de segurança, especialmente em repositórios versionados. Devem ser externalizadas em variáveis de ambiente ou arquivos de configuração protegidos.

### 2.7 Gerenciamento de Recursos
Nenhum dos recursos JDBC (`Connection`, `Statement`, `ResultSet`) é fechado após o uso. Isso causa:
- **Vazamento de conexões** com o banco de dados.
- Possível esgotamento do pool de conexões em produção.

A solução moderna é usar `try-with-resources`.

### 2.8 Senhas em Texto Puro
A senha é comparada diretamente como texto puro no banco de dados, sem qualquer mecanismo de hash (bcrypt, Argon2, etc.). Isso viola práticas fundamentais de segurança de credenciais.

### 2.9 Acoplamento
O método `conectarBD()` está acoplado diretamente à implementação (MySQL, endereço fixo). A ausência de injeção de dependência impossibilita testes unitários sem um banco de dados real.

---

## 3. Grafo de Fluxo

O grafo foi construído para o método `verificarUsuario`, que concentra a lógica principal e as estruturas de decisão.
<div align="center">
<img> src="https://github.com/LeandroMurafer/ATIVIDADE-INDIVIDUAL---TESTE-DE-CAIXA-BRANCA-E-REVISAO-DE-CODIGO-FONTE/blob/cdee85af350826db33b5cfc8a253aa67adfdbe19/Grafo_de_Fluxo_RA248670.png" width="400">
</div>
### Identificação dos Nós

| Nó  | Descrição |
|-----|-----------|
| N1  | Início do método |
| N2  | Declaração de `sql = ""` e chamada `conectarBD()` |
| N3  | Montagem da string SQL (3 linhas de concatenação) |
| N4  | Bloco `try` — `conn.createStatement()` |
| N5  | `st.executeQuery(sql)` |
| N6  | Decisão: `rs.next()` — há registro? |
| N7  | `result = true` e `nome = rs.getString("nome")` |
| N8  | `catch (Exception e)` — tratamento vazio |
| N9  | `return result` |
| N10 | Fim do método |

### Identificação das Arestas

| Aresta | De → Para | Condição |
|--------|-----------|----------|
| E1  | N1 → N2 | Sequencial |
| E2  | N2 → N3 | Sequencial |
| E3  | N3 → N4 | Sequencial (entra no try) |
| E4  | N4 → N5 | Sequencial |
| E5  | N5 → N6 | Sequencial |
| E6  | N6 → N7 | `rs.next() == true` |
| E7  | N6 → N9 | `rs.next() == false` |
| E8  | N7 → N9 | Sequencial (após bloco if) |
| E9  | N4 → N8 | Exceção lançada em createStatement |
| E10 | N5 → N8 | Exceção lançada em executeQuery |
| E11 | N8 → N9 | Saída do catch |
| E12 | N9 → N10 | Sequencial |
| E13 | N2 → N8 | Exceção lançada em conectarBD (NullPointer) |

> O grafo foi gerado e está disponível na imagem `grafo_fluxo.svg` neste repositório.

---

## 4. Complexidade Ciclomática

### Fórmula aplicada

```
V(G) = E − N + 2P
```

Onde:
- **E** = número de arestas = **13**
- **N** = número de nós = **10**
- **P** = número de componentes conexos (grafos independentes) = **1**

### Cálculo

```
V(G) = 13 − 10 + 2 × 1
V(G) = 3 + 2
V(G) = 5
```

### Interpretação

| V(G) | Risco |
|------|-------|
| 1–10 | Baixo — código simples e testável |
| 11–20 | Moderado |
| 21–50 | Alto |
| > 50  | Crítico |

O valor **V(G) = 5** indica baixa complexidade ciclomática, porém o código possui riscos de segurança que não se refletem nesse número — reforçando que a complexidade ciclomática mede estrutura de decisão, não qualidade ou segurança.

---

## 5. Caminhos Básicos

Com V(G) = 5, existem **5 caminhos linearmente independentes**:

### Caminho 1 — Fluxo principal sem resultado
```
N1 → N2 → N3 → N4 → N5 → N6 → N9 → N10
```
**Cenário**: Conexão bem-sucedida, query executada, mas nenhum usuário encontrado (`rs.next()` retorna false).  
**Resultado**: `result = false` (valor inicial).

---

### Caminho 2 — Fluxo principal com resultado encontrado
```
N1 → N2 → N3 → N4 → N5 → N6 → N7 → N9 → N10
```
**Cenário**: Conexão bem-sucedida, query executada, usuário encontrado.  
**Resultado**: `result = true`, `nome` preenchido.

---

### Caminho 3 — Exceção no `createStatement`
```
N1 → N2 → N3 → N4 → N8 → N9 → N10
```
**Cenário**: Falha ao criar o Statement (ex.: conexão nula ou fechada).  
**Resultado**: Exceção capturada silenciosamente, `result = false`.

---

### Caminho 4 — Exceção no `executeQuery`
```
N1 → N2 → N3 → N4 → N5 → N8 → N9 → N10
```
**Cenário**: Falha ao executar a SQL (ex.: SQL malformada, tabela inexistente).  
**Resultado**: Exceção capturada silenciosamente, `result = false`.

---

### Caminho 5 — NullPointerException por conexão nula
```
N1 → N2 → N8 → N9 → N10
```
**Cenário**: `conectarBD()` retorna `null` (driver não encontrado ou falha de conexão). O uso de `conn.createStatement()` lança `NullPointerException`.  
**Resultado**: Exceção capturada silenciosamente, `result = false`.

---

### Relação dos caminhos com casos de teste

| Caminho | Caso de Teste |
|---------|---------------|
| C1 | Login/senha corretos mas não cadastrados |
| C2 | Login/senha válidos e existentes no banco |
| C3 | Banco de dados indisponível — falha no Statement |
| C4 | Tabela `usuarios` inexistente ou SQL inválida |
| C5 | Driver MySQL ausente ou URL de conexão inválida |

---

## 6. Melhorias Implementadas

O código revisado (`UserRefatorado.java`) corrige todas as falhas identificadas:

### 6.1 Eliminação de SQL Injection — `PreparedStatement`
```java
String sql = "SELECT nome FROM usuarios WHERE login = ? AND senha = ?";
PreparedStatement ps = conn.prepareStatement(sql);
ps.setString(1, login);
ps.setString(2, DigestUtils.sha256Hex(senha)); // hash da senha
```

### 6.2 Credenciais externalizadas
```java
String url = System.getenv("DB_URL");
String user = System.getenv("DB_USER");
String pass = System.getenv("DB_PASSWORD");
conn = DriverManager.getConnection(url, user, pass);
```

### 6.3 Fechamento garantido de recursos — `try-with-resources`
```java
try (PreparedStatement ps = conn.prepareStatement(sql);
     ResultSet rs = ps.executeQuery()) {
    // uso dos recursos — fechados automaticamente
}
```

### 6.4 Tratamento de exceções com log
```java
} catch (SQLException e) {
    System.err.println("[ERRO] Falha na verificação de usuário: " + e.getMessage());
}
```

### 6.5 Hash de senha (SHA-256 como exemplo mínimo)
Em produção, recomenda-se BCrypt ou Argon2. O código revisado demonstra o princípio.

### 6.6 JavaDoc e comentários explicativos
Todos os métodos foram documentados com JavaDoc descrevendo parâmetros, retorno e comportamento.

### 6.7 Separação de responsabilidades
O método `conectarBD()` agora lança `SQLException` ao invés de retornar `null` silenciosamente, tornando falhas explícitas para o chamador.

---

## 7. Conclusão

### Importância do Teste Estrutural
O teste de caixa branca permite examinar todos os caminhos de execução do código, incluindo os caminhos de erro que raramente são exercitados em testes funcionais. Neste caso, o caminho de exceção (`catch` vazio) seria invisível em testes caixa-preta, mas é crítico para a confiabilidade do sistema.

### Dificuldades Encontradas
A principal dificuldade foi mapear com precisão as arestas relacionadas a exceções, uma vez que o fluxo de erro não é explicitamente visível no código — ele depende do conhecimento das exceções que cada chamada de método pode lançar.

### Impacto da Revisão de Código
A revisão revelou que o código original, embora funcional em ambiente controlado, seria completamente inseguro em produção. A SQL Injection possibilitaria acesso não autorizado irrestrito ao sistema. A refatoração eliminou todos os vetores de ataque identificados e melhorou significativamente a robustez e a manutenibilidade.

### Importância da Qualidade de Software
Este exercício demonstra que código funcional e código de qualidade são conceitos distintos. Um sistema pode "funcionar" e ainda assim ser vulnerável, impossível de manter, não testável e propenso a falhas silenciosas em produção. Práticas como revisão de código, testes estruturais e análise estática são investimentos que reduzem custos e riscos a longo prazo.
