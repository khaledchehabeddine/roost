import org.gradle.api.publish.maven.MavenPublication
import org.gradle.api.publish.PublishingExtension
import org.gradle.plugins.signing.SigningExtension

plugins {
    id("com.android.library")
    id("org.jetbrains.kotlin.android")
    id("maven-publish")
    id("signing")
}

val aetherVersion = rootProject.extensions.extraProperties["aetherVersion"] as String
val aetherMavenRepo = rootProject.extensions.extraProperties["aetherMavenRepo"] as String
val generatedKotlinDir = rootProject.layout.projectDirectory.dir("../../target/android/kotlin")
val generatedJniLibsDir = rootProject.layout.projectDirectory.dir("../../target/android/jniLibs")

android {
    namespace = "com.aurelion.aether"
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
            java.srcDir(generatedKotlinDir)
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
        groupId = "com.aurelion"
        artifactId = "aether"
        version = aetherVersion

        pom {
            name.set("Aether Android")
            description.set("Android UniFFI bindings and native libraries for Aether.")
            url.set("https://github.com/RelayNet/aether")
                    licenses {
                        license {
                            name.set("All rights reserved")
                            url.set("https://github.com/RelayNet/aether/blob/main/LICENSE")
                        }
                    }
            developers {
                developer {
                    id.set("aurelion")
                    name.set("Aurelion")
                }
            }
            scm {
                connection.set("scm:git:https://github.com/RelayNet/aether.git")
                developerConnection.set("scm:git:ssh://git@github.com/RelayNet/aether.git")
                url.set("https://github.com/RelayNet/aether")
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
