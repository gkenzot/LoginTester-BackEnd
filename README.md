# Login Auth API

API de autenticação e autorização desenvolvida com Spring Boot 3.2.4.

## 🚀 Tecnologias Utilizadas

- Java 21
- Spring Boot 3.2.4
- Spring Security
- Spring Data JPA
- MySQL
- JWT (JSON Web Tokens)
- Lombok
- Swagger/OpenAPI

## 📋 Pré-requisitos

- Java 21 ou superior
- Maven
- MySQL
- IDE de sua preferência (recomendado: IntelliJ IDEA ou Eclipse)

### Instalação do Maven no Windows

1. Baixe o Maven:
   - Acesse [https://maven.apache.org/download.cgi](https://maven.apache.org/download.cgi)
   - Baixe o arquivo binário (apache-maven-x.x.x-bin.zip)

2. Extraia o arquivo:
   - Crie uma pasta em `C:\Program Files\Apache\maven`
   - Extraia o conteúdo do zip para esta pasta

3. Configure as variáveis de ambiente:
   - Abra o Painel de Controle > Sistema > Configurações avançadas do sistema
   - Clique em "Variáveis de Ambiente"
   - Em "Variáveis do Sistema", clique em "Novo"
   - Nome da variável: `MAVEN_HOME`
   - Valor da variável: `C:\Program Files\Apache\maven`
   - Encontre a variável "Path" e clique em "Editar"
   - Clique em "Novo" e adicione: `%MAVEN_HOME%\bin`

4. Verifique a instalação:
   - Abra um novo prompt de comando
   - Execute: `mvn -version`

## 🔧 Configuração do Ambiente

1. Clone o repositório:
```bash
git clone [URL_DO_REPOSITÓRIO]
```

2. Configure o banco de dados MySQL:
   - Crie um banco de dados chamado `login_auth`
   - Configure as credenciais no arquivo `application.properties`

3. Execute o script SQL inicial (se houver) na pasta `sql/`

## 🚀 Executando o Projeto

1. Compile o projeto:
```bash
mvnw.cmd clean install
mvn clean install
.\mvnw clean install
```

2. Execute a aplicação:
```bash
mvnw.cmd spring-boot:run
.\mvnw spring-boot:run
mvn spring-boot:run -Dspring-boot.run.jvmArguments="-Xmx256m -Xms128m"
```

A aplicação estará disponível em `https://localhost:8443`

## 📚 Documentação da API

A documentação Swagger está disponível em:
```
http://localhost:8080/swagger-ui.html
```

## 🔐 Segurança

- A API utiliza JWT para autenticação
- Senhas são armazenadas com hash seguro
- Implementação de Spring Security para proteção dos endpoints

## 🛠️ Estrutura do Projeto

```
src/
├── main/
│   ├── java/
│   │   └── com/example/
│   │       ├── config/
│   │       ├── controller/
│   │       ├── model/
│   │       ├── repository/
│   │       ├── service/
│   │       └── security/
│   └── resources/
│       └── application.properties
└── test/
```

## 🤝 Contribuindo

1. Faça um Fork do projeto
2. Crie uma Branch para sua Feature (`git checkout -b feature/AmazingFeature`)
3. Faça o Commit das suas mudanças (`git commit -m 'Add some AmazingFeature'`)
4. Faça o Push para a Branch (`git push origin feature/AmazingFeature`)
5. Abra um Pull Request

## 📝 Licença

Este projeto está sob a licença MIT. Veja o arquivo [LICENSE](LICENSE) para mais detalhes. 