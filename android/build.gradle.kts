plugins {
    id("com.android.library") version "9.4.1"
    `maven-publish`
}

group = "com.chirp"
version = file("../Cargo.toml").readLines().first { it.startsWith("version = ") }.split('"')[1]

android {
    namespace = "com.chirp.roost"
    compileSdk = 36
    ndkVersion = "29.0.14206865"

    defaultConfig {
        minSdk = 21
        consumerProguardFiles("consumer-rules.pro")
    }

    sourceSets {
        getByName("main") {
            kotlin.directories += "../target/android/kotlin"
            jniLibs.directories += "../target/android/jniLibs"
        }
    }

    publishing {
        singleVariant("release") {
            withSourcesJar()
        }
    }
}

dependencies {
    api("net.java.dev.jna:jna:5.19.1@aar")
}

publishing {
    publications {
        register<MavenPublication>("release") {
            afterEvaluate { from(components["release"]) }
        }
    }

    repositories {
        maven {
            name = "Local"
            url = uri("../target/android/maven")
        }

        maven {
            name = "GitHubPackages"
            url = uri("https://maven.pkg.github.com/khaledchehabeddine/roost-kotlin")
            credentials(PasswordCredentials::class)
        }
    }
}
