# Etapa 1: Build do JAR
FROM maven:3.9.8-eclipse-temurin-21 AS build
WORKDIR /app

# Debug: Mostra o diretório atual e seu conteúdo antes do build
RUN pwd && ls -la

# Copia todos os arquivos do projeto para o diretório /app
COPY . .

# Debug: Mostra o conteúdo após a cópia
RUN echo "=== Conteúdo após COPY ===" && ls -la

# Mostra a estrutura do projeto antes do build
RUN echo "=== Estrutura do projeto antes do build ===" && \
    ls -R

# Realiza o build do projeto e gera o JAR com output detalhado
RUN echo "=== Maven Version ===" && \
    mvn --version && \
    echo "=== Conteúdo do pom.xml ===" && \
    cat pom.xml && \
    echo "=== Iniciando build com debug ===" && \
    mvn clean package -DskipTests -X

# Debug: Mostra detalhadamente o conteúdo após o build
RUN echo "=== Conteúdo do diretório atual ===" && \
    ls -la && \
    echo "=== Conteúdo detalhado do target ===" && \
    find . -name "*.jar" -type f -ls

# Etapa 2: Imagem final
FROM eclipse-temurin:21-jre

WORKDIR /app

# Debug: Verifica o diretório antes da cópia
RUN echo "=== Diretório antes da cópia do JAR ===" && ls -la /app/

# Copia o JAR gerado na etapa anterior para a imagem final
COPY --from=build /app/target/login-auth-api-0.0.1-SNAPSHOT.jar app.jar

# Debug: Verifica se o JAR foi copiado e suas permissões
RUN echo "=== Verificando JAR copiado ===" && \
    ls -la /app/ && \
    echo "=== Verificando permissões do JAR ===" && \
    stat app.jar && \
    echo "=== Verificando tamanho do JAR ===" && \
    du -h app.jar

EXPOSE 8080

# Comando para rodar a aplicação com debug adicional
CMD ["sh", "-c", "echo '=== Verificando ambiente de execução ===' && \
     java -version && \
     echo '=== Conteúdo do diretório de trabalho ===' && \
     pwd && ls -la && \
     echo '=== Executando JAR ===' && \
     java -jar app.jar"]
