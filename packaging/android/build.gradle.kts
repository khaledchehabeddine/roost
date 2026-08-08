plugins {
    id("com.android.application") version "9.2.0" apply false
    id("com.android.library") version "9.2.0" apply false
    id("org.jetbrains.kotlin.android") version "2.4.0" apply false
}

val aetherVersionProvider = providers.gradleProperty("aetherVersion")
    .orElse(providers.environmentVariable("AETHER_ANDROID_VERSION"))
    .orElse("0.0.0-dev")
val aetherMavenRepoProvider = providers.gradleProperty("aetherMavenRepo")
    .orElse(providers.environmentVariable("AETHER_ANDROID_MAVEN_REPO"))
    .orElse(layout.projectDirectory.dir("../../target/android/maven").asFile.absolutePath)
val aetherArtifactIdProvider = providers.gradleProperty("aetherArtifactId")
    .orElse(providers.environmentVariable("AETHER_ANDROID_ARTIFACT_ID"))
    .orElse("aether")

allprojects {
    group = "com.aurelion"
    version = aetherVersionProvider.get()

    extensions.extraProperties["aetherVersion"] = aetherVersionProvider.get()
    extensions.extraProperties["aetherMavenRepo"] = aetherMavenRepoProvider.get()
    extensions.extraProperties["aetherArtifactId"] = aetherArtifactIdProvider.get()
}
