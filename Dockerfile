# syntax=docker/dockerfile:1
FROM maven:3.9.6-eclipse-temurin-21 AS build
WORKDIR /app


COPY pom.xml .
RUN mvn dependency:go-offline

COPY src ./src
RUN mvn clean package -DskipTests

FROM amazoncorretto:21-alpine
WORKDIR /app

COPY --from=build /app/target/api-gateway-0.0.1-SNAPSHOT.jar api.jar

EXPOSE 8080
ENTRYPOINT ["java","-XX:+UseG1GC","-XX:+UseStringDeduplication","-jar","api.jar"]
