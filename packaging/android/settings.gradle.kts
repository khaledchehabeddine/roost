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
                includeGroup("com.aurelion")
            }
        }
        google()
        mavenCentral()
    }
}

rootProject.name = "aether-android-distribution"

include(":aether")
include(":consumer")
