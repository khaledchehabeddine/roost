import com.android.build.api.dsl.ManagedVirtualDevice

plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val aetherVersion = rootProject.extensions.extraProperties["aetherVersion"] as String
val issue122CoverageSource = rootProject.layout.projectDirectory
    .file("../../crates/aether-uniffi/tests/bindings/Issue122Coverage.kt")
val generatedCoverageDir = layout.buildDirectory.dir("generated/androidTest/kotlin")

android {
    namespace = "com.aurelion.aether.consumer"
    compileSdk = 36

    defaultConfig {
        applicationId = "com.aurelion.aether.consumer"
        minSdk = 36
        targetSdk = 36
        versionCode = 1
        versionName = aetherVersion
        testInstrumentationRunner = "android.test.InstrumentationTestRunner"
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    sourceSets {
        getByName("androidTest") {
            java.srcDir(generatedCoverageDir)
        }
    }

    testOptions {
        managedDevices {
            localDevices {
                create<ManagedVirtualDevice>("pixel6Api36") {
                    device = "Pixel 6"
                    apiLevel = 36
                    systemImageSource = "aosp-atd"
                }
            }
        }
    }
}

kotlin {
    jvmToolchain(17)
}

dependencies {
    implementation("com.aurelion:aether:$aetherVersion")
}

val copyIssue122Coverage by tasks.registering(Copy::class) {
    from(issue122CoverageSource)
    into(generatedCoverageDir)
}

tasks.configureEach {
    if (name.contains("AndroidTest", ignoreCase = true)) {
        dependsOn(copyIssue122Coverage)
    }
}
