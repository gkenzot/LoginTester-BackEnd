# Etapa 1: Build do JAR
FROM maven:3.9.8-eclipse-temurin-21 AS build
WORKDIR /app

# Copia todos os arquivos do projeto para o diretório /app
COPY . .

# Realiza o build do projeto e gera o JAR
RUN mvn clean package -DskipTests

# Verifica o conteúdo do diretório target para garantir que o arquivo JAR foi gerado corretamente
RUN ls -la /app/target/

# Etapa 2: Imagem final
FROM eclipse-temurin:21-jre

WORKDIR /app

# Copia o JAR gerado na etapa anterior para a imagem final
COPY --from=build /app/target/login-auth-api-0.0.1-SNAPSHOT.jar app.jar

# Verifica se o JAR foi copiado corretamente
RUN ls -la /app/

EXPOSE 8080

# Comando para rodar a aplicação
ENTRYPOINT ["java", "-jar", "app.jar"]
