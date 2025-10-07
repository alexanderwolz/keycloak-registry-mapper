ARG ALPINE_VERSION="3.18.0"
ARG KEYCLOAK_VERSION="26.4.1"
ARG MAPPER_VERSION="1.8.0"
ARG MAPPER_LIB="keycloak-registry-mapper-${MAPPER_VERSION}.jar"

# stage 1: mapper build
FROM openjdk:16-jdk-slim-buster as mapper 
LABEL maintainer="mail@alexanderwolz.de"
WORKDIR /mapper
COPY gradle gradle
COPY gradlew gradlew
COPY gradle.properties gradle.properties
COPY settings.gradle settings.gradle
RUN ./gradlew # Cache gradle downloads for successive builds
COPY build.gradle build.gradle
COPY src src
RUN ./gradlew clean build --stacktrace

# stage 2: keycloak build
FROM keycloak/keycloak:${KEYCLOAK_VERSION} as builder
LABEL maintainer="mail@alexanderwolz.de"
ARG MAPPER_LIB
COPY --from=mapper /mapper/build/libs/${MAPPER_LIB} /opt/keycloak/providers/
ENV KC_FEATURES=docker,token-exchange
ENV KC_DB=mariadb
RUN /opt/keycloak/bin/kc.sh build

## stage 3: runtime
FROM keycloak/keycloak:${KEYCLOAK_VERSION} as runtime
LABEL maintainer="mail@alexanderwolz.de"
COPY --from=builder /opt/keycloak/lib/quarkus/ /opt/keycloak/lib/quarkus/
COPY --from=builder /opt/keycloak/providers/ /opt/keycloak/providers/
WORKDIR /opt/keycloak
ENV KEYCLOAK_ADMIN=admin
ENV KEYCLOAK_ADMIN_PASSWORD=admin
ENV KC_DB_URL=jdbc:mariadb://database:3306/database
ENV KC_DB_USERNAME=keycloak
ENV KC_DB_PASSWORD=keycloak
ENV KC_HOSTNAME=localhost
ENV KC_HOSTNAME_STRICT=false
ENV KC_PROXY=edge
ENV KC_HTTP_ENABLED=true
ENTRYPOINT ["/opt/keycloak/bin/kc.sh"]
CMD ["start", "--optimized"]
