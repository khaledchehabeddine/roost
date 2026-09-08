import org.gradle.api.publish.maven.MavenPublication
import org.gradle.api.publish.PublishingExtension
import org.gradle.plugins.signing.SigningExtension

plugins {
    // AGP 9.0+ provides built-in Kotlin support; applying org.jetbrains.kotlin.android
    // is now an error (see https://kotl.in/gradle/agp-built-in-kotlin).
    id("com.android.library")
    id("maven-publish")
    id("signing")
}

val aetherVersion = rootProject.extensions.extraProperties["aetherVersion"] as String
val aetherMavenRepo = rootProject.extensions.extraProperties["aetherMavenRepo"] as String
val aetherArtifactId = rootProject.extensions.extraProperties["aetherArtifactId"] as String
val generatedKotlinDir = rootProject.layout.projectDirectory.dir("../../target/android/kotlin")
val generatedJniLibsDir = rootProject.layout.projectDirectory.dir("../../target/android/jniLibs")

android {
    namespace = "io.github.relaynet.roost"
    compileSdk = 36

    defaultConfig {
        minSdk = 36

        aarMetadata {
            minCompileSdk = 36
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("main") {
            // AGP 9 built-in Kotlin compiles the `kotlin` source set; the generated UniFFI
            // bindings must be registered there (not `java`), otherwise compileReleaseKotlin
            // reports NO-SOURCE and the published AAR ships an empty classes.jar.
            kotlin.srcDir(generatedKotlinDir)
            jniLibs.srcDir(generatedJniLibsDir)
        }
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    api("net.java.dev.jna:jna:5.18.1@aar")
}

publishing {
    repositories {
        maven {
            name = "AetherLocal"
            url = uri(aetherMavenRepo)
        }
    }
}

afterEvaluate {
    val publishingExtension = extensions.getByType<PublishingExtension>()
    val releasePublication = publishingExtension.publications.create<MavenPublication>("release") {
        from(components["release"])
        groupId = "io.github.relaynet"
        artifactId = aetherArtifactId
        version = aetherVersion

        pom {
            name.set("Roost")
            description.set("Android UniFFI bindings and native libraries for Roost.")
            url.set("https://github.com/RelayNet/roost-kotlin")
                    licenses {
                        license {
                            name.set("All rights reserved")
                            url.set("https://github.com/RelayNet/roost/blob/main/LICENSE")
                        }
                    }
            developers {
                developer {
                    id.set("aurelion")
                    name.set("Aurelion")
                }
            }
            scm {
                connection.set("scm:git:https://github.com/RelayNet/roost.git")
                developerConnection.set("scm:git:ssh://git@github.com/RelayNet/roost.git")
                url.set("https://github.com/RelayNet/roost")
            }
        }
    }

    extensions.configure<SigningExtension>("signing") {
        val signingEnabled = providers.gradleProperty("aetherSignPublication")
            .map { it.toBooleanStrict() }
            .orElse(false)
        val signingKey = providers.gradleProperty("signingInMemoryKey")
        val signingPassword = providers.gradleProperty("signingInMemoryKeyPassword")

        isRequired = signingEnabled.get()
        if (signingEnabled.get()) {
            useInMemoryPgpKeys(signingKey.get(), signingPassword.get())
            sign(releasePublication)
        }
    }
}
