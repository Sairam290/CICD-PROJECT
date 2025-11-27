FROM maven:3.8.8-eclipse-temurin-21 AS build
WORKDIR /build

# copy pom.xml
COPY pom.xml ./

# Download dependencies to speed up later builds
RUN mvn -B -q dependency:go-offline

# copy source and build the jar
COPY src ./src
RUN mvn -B -q package -DskipTests

FROM eclipse-temurin:21-jre
WORKDIR /app
COPY --from=build /build/target/*.jar app.jar

EXPOSE 8085
ENV SPRING_PROFILES_ACTIVE=prod
ENTRYPOINT ["sh","-c","java $JAVA_OPTS -jar /app/app.jar"]
