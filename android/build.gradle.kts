plugins {
    id("com.android.library") version "9.2.0"
    `maven-publish`
}

group = "com.chirp"

android {
    namespace = "com.chirp.roost"
    compileSdk = 36

    defaultConfig {
        minSdk = 36
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
    api("net.java.dev.jna:jna:5.18.1@aar")
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
            url = uri("https://maven.pkg.github.com/chirp-org/roost-kotlin")
            credentials(PasswordCredentials::class)
        }
    }
}
