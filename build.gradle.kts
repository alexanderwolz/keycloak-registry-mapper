import java.util.Base64

plugins {
    kotlin("jvm") version "2.2.10"
    id("java-library")
    id("io.github.gradle-nexus.publish-plugin") version "1.3.0"
    id("maven-publish")
    jacoco
    signing
}

val keycloakVersion = "26.4.0"

group = "de.alexanderwolz"
version = "1.8.0"

repositories {
    mavenCentral()
    mavenLocal()
    maven("https://repo1.maven.org/maven2")
}

java {
    withSourcesJar()
    withJavadocJar()
    sourceCompatibility = JavaVersion.VERSION_21
    targetCompatibility = JavaVersion.VERSION_21
}

kotlin {
    //Keycloak 25 relies on JDK 21
    jvmToolchain(21)
}

dependencies {
    compileOnly("org.keycloak:keycloak-core:$keycloakVersion")
    compileOnly("org.keycloak:keycloak-services:$keycloakVersion")
    compileOnly("org.keycloak:keycloak-server-spi:$keycloakVersion")
    compileOnly("org.keycloak:keycloak-server-spi-private:$keycloakVersion")

    implementation("de.alexanderwolz:commons-util:1.4.7")
    runtimeOnly("org.jboss.slf4j:slf4j-jboss-logmanager:2.0.1.Final")

    testImplementation("org.jetbrains.kotlin:kotlin-test")
    testImplementation("org.mockito.kotlin:mockito-kotlin:5.1.0")
    testImplementation("org.keycloak:keycloak-core:$keycloakVersion")
    testImplementation("org.keycloak:keycloak-services:$keycloakVersion")
    testImplementation("org.keycloak:keycloak-server-spi:$keycloakVersion")
    testImplementation("org.keycloak:keycloak-server-spi-private:$keycloakVersion")
}

tasks.test {
    useJUnitPlatform()
    finalizedBy(tasks.jacocoTestReport)
    systemProperty("java.util.logging.config.file", "${projectDir}/src/test/resources/logging.properties")
}

jacoco {
    toolVersion = "0.8.11"
}

tasks.jacocoTestReport {
    dependsOn(tasks.test)
    reports {
        xml.required.set(true)
        html.required.set(true)
    }
}

tasks.jar {
    manifest {
        attributes(
            "Implementation-Title" to project.name,
            "Implementation-Version" to project.version,
            "Implementation-Vendor" to "Alexander Wolz",
            "Built-By" to System.getProperty("user.name"),
            "Built-JDK" to System.getProperty("java.version"),
            "Created-By" to "Gradle ${gradle.gradleVersion}"
        )
    }

    //create fat jar
    //TODO remove and just add org.jetbrains.kotlin:kotlin-stdlib
    duplicatesStrategy = DuplicatesStrategy.EXCLUDE
    from(configurations
        .runtimeClasspath
        .get()
        .map { if (it.isDirectory) it else zipTree(it) }
    )
}


//see also https://github.com/gradle-nexus/publish-plugin/tree/v2.0.0
publishing {
    publications {
        create<MavenPublication>("mavenJava") {
            from(components["java"])
            pom {
                name.set("Keycloak Role and Groups Mapper for Docker Registry V2")
                description.set("Authorization Mapping Provider for Keycloak's Docker Registry v2 token protocol based on client roles and realm groups with configuration options.")
                url.set("https://github.com/alexanderwolz/keycloak-docker-group-role-mapper")
                licenses {
                    license {
                        name.set("Apache License 2.0")
                        url.set("https://www.apache.org/licenses/LICENSE-2.0")
                    }
                }
                developers {
                    developer {
                        id.set("alexanderwolz")
                        name.set("Alexander Wolz")
                        url.set("https://www.alexanderwolz.de")
                    }
                }
                scm {
                    connection.set("scm:git:https://github.com/alexanderwolz/keycloak-docker-group-role-mapper.git")
                    developerConnection.set("scm:git:ssh://git@github.com/alexanderwolz/keycloak-docker-group-role-mapper.git")
                    url.set("https://github.com/alexanderwolz/keycloak-docker-group-role-mapper")
                }
            }
        }
    }
}

signing {
    val signingKey = System.getenv("GPG_PRIVATE_KEY")
    val signingPassword = System.getenv("GPG_PASSPHRASE")

    if (signingKey != null && signingPassword != null) {
        logger.info("GPG credentials found in System")
        val decodedKey = String(Base64.getDecoder().decode(signingKey))
        useInMemoryPgpKeys(decodedKey, signingPassword)
        sign(publishing.publications["mavenJava"])
    } else {
        logger.info("No GPG credentials found in System, using cmd..")
        useGpgCmd()
        sign(publishing.publications["mavenJava"])
    }
}

nexusPublishing {
    repositories {
        sonatype {
            nexusUrl.set(uri("https://ossrh-staging-api.central.sonatype.com/service/local/"))
            snapshotRepositoryUrl.set(uri("https://central.sonatype.com/repository/maven-snapshots/"))
            username.set(System.getenv("SONATYPE_USERNAME"))
            password.set(System.getenv("SONATYPE_PASSWORD"))
        }
    }
}
