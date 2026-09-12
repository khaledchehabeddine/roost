import org.gradle.api.publish.maven.MavenPublication
import org.gradle.api.publish.PublishingExtension

plugins {
    // AGP 9.0+ provides built-in Kotlin support; applying org.jetbrains.kotlin.android
    // is now an error (see https://kotl.in/gradle/agp-built-in-kotlin).
    id("com.android.library")
    id("maven-publish")
}

val roostVersion = providers.gradleProperty("roostVersion").get()
val roostArtifactId = providers.gradleProperty("roostArtifactId").get()
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
            name = "Local"
            url = uri(rootProject.file("../../target/android/maven"))
        }
    }
}

afterEvaluate {
    val publishingExtension = extensions.getByType<PublishingExtension>()
    publishingExtension.publications.create<MavenPublication>("release") {
        from(components["release"])
        groupId = "io.github.relaynet"
        artifactId = roostArtifactId
        version = roostVersion

        pom {
            name.set("Roost")
            description.set("Kotlin bindings and native libraries for Roost")
            url.set("https://github.com/RelayNet/roost-kotlin")
        }
    }
}

tasks.withType<AbstractArchiveTask>().configureEach {
    isPreserveFileTimestamps = false
    isReproducibleFileOrder = true
}
