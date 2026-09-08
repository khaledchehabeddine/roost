pluginManagement {
    repositories {
        google()
        mavenCentral()
        gradlePluginPortal()
    }
}

val aetherMavenRepo = providers.gradleProperty("aetherMavenRepo")
    .orElse(providers.environmentVariable("AETHER_ANDROID_MAVEN_REPO"))
    .orElse(file("../../target/android/maven").absolutePath)

dependencyResolutionManagement {
    repositoriesMode.set(RepositoriesMode.FAIL_ON_PROJECT_REPOS)
    repositories {
        exclusiveContent {
            forRepository {
                maven {
                    url = uri(aetherMavenRepo.get())
                }
            }
            filter {
                includeGroup("io.github.relaynet")
            }
        }
        google()
        mavenCentral()
    }
}

rootProject.name = "roost-android-distribution"

include(":roost")
include(":consumer")
