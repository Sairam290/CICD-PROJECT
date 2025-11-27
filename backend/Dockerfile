FROM maven:3.8.8-eclipse-temurin-21 AS build
WORKDIR /build

# copy pom + mvnw so the wrapper can bootstrap maven
COPY pom.xml mvnw* ./
COPY .mvn .mvn
RUN if [ -f mvnw ]; then chmod +x mvnw; fi || true

# Download dependencies to speed up later builds
RUN if [ -f mvnw ]; then ./mvnw -B -q dependency:go-offline; else mvn -B -q dependency:go-offline; fi

# copy source and build the jar
COPY src ./src
RUN if [ -f mvnw ]; then ./mvnw -B -q package -DskipTests; else mvn -B -q package -DskipTests; fi

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /build/target/*.jar app.jar

EXPOSE 8085
ENV SPRING_PROFILES_ACTIVE=prod
ENTRYPOINT ["sh","-c","java $JAVA_OPTS -jar /app/app.jar"]
