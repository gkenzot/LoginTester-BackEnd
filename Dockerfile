# Etapa 1: Build do JAR
FROM maven:3.9.8-eclipse-temurin-21 AS build
WORKDIR /app

# Copia primeiro só o pom.xml
COPY pom.xml .

# Download de dependências em uma camada separada (resiliente)
RUN mvn -q -U -DskipTests -DincludeScope=test dependency:go-offline || true

# Agora copia o código fonte
COPY src src

# Faz o build com debug completo
RUN echo "=== Versão do Maven ===" && \
    mvn --version && \
    echo "=== Estrutura do Projeto ===" && \
    find . -type f && \
    echo "=== Conteúdo do pom.xml ===" && \
    cat pom.xml && \
    echo "=== Iniciando build com debug completo ===" && \
    mvn clean package -e -X -DskipTests && \
    echo "=== Arquivos JAR gerados ===" && \
    find . -name "*.jar" -type f -ls && \
    echo "=== Conteúdo do diretório target ===" && \
    ls -la target/

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

# Comando para rodar a aplicação com configurações altamente otimizadas para baixo consumo de memória
CMD ["sh", "-c", "echo '=== Verificando ambiente de execução ===' && \
     java -version && \
     echo '=== Variáveis de ambiente configuradas ===' && \
     (env | grep -E 'DB_|JWT_|SPRING_|SSL_' | cut -d= -f1 || true) && \
     echo '=== Conteúdo do diretório de trabalho ===' && \
     pwd && ls -la && \
     echo '=== Executando JAR com configurações otimizadas ===' && \
     java \
     -Xmx400m \
     -Xms200m \
     -XX:MaxMetaspaceSize=120m \
     -XX:CompressedClassSpaceSize=24m \
     -Xss512k \
     -XX:InitialCodeCacheSize=16m \
     -XX:ReservedCodeCacheSize=48m \
     -XX:MaxDirectMemorySize=10M \
     -XX:+UseG1GC \
     -XX:+UseStringDeduplication \
     -XX:+UseCompressedOops \
     -XX:G1HeapRegionSize=4m \
     -XX:GCTimeRatio=4 \
     -XX:AdaptiveSizePolicyWeight=90 \
     -XX:MinHeapFreeRatio=20 \
     -XX:MaxHeapFreeRatio=40 \
     -XX:+ExitOnOutOfMemoryError \
     -Djava.security.egd=file:/dev/./urandom \
     -Dspring.config.location=classpath:/application.properties \
     -Dserver.tomcat.max-threads=10 \
     -Dserver.tomcat.min-spare-threads=2 \
     -Dspring.jpa.open-in-view=false \
     -Dspring.main.lazy-initialization=true \
     -Dspring.jmx.enabled=false \
     -jar app.jar"]
