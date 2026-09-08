import com.android.build.api.dsl.ManagedVirtualDevice

plugins {
    // AGP 9.0+ provides built-in Kotlin support; applying org.jetbrains.kotlin.android
    // is now an error (see https://kotl.in/gradle/agp-built-in-kotlin).
    id("com.android.application")
}

val aetherVersion = rootProject.extensions.extraProperties["aetherVersion"] as String
val issue122CoverageSource = rootProject.layout.projectDirectory
    .file("../../crates/roost-client/tests/bindings/Issue122Coverage.kt")
val generatedCoverageDir = layout.buildDirectory.dir("generated/androidTest/kotlin")

android {
    namespace = "io.github.relaynet.roost.consumer"
    compileSdk = 36

    // The smoke test uses the legacy android.test instrumentation framework, which moved out of
    // android.jar into optional libraries; pull them onto the compile classpath.
    useLibrary("android.test.runner")
    useLibrary("android.test.base")

    defaultConfig {
        applicationId = "io.github.relaynet.roost.consumer"
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

    testOptions {
        managedDevices {
            // AGP 9: `localDevices` is monomorphic; the polymorphic typed create moved to `allDevices`.
            allDevices {
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
    implementation("io.github.relaynet:roost:$aetherVersion")
}

// The issue-122 regression coverage lives outside this Gradle project. Stage it into a
// generated Kotlin source dir and wire it onto the androidTest variant via the AGP 9 variant
// API: under built-in Kotlin, generated sources must be added through the `kotlin` source set's
// addGeneratedSourceDirectory (the old `androidTest { java.srcDir(provider) }` form is rejected
// and would not compile a Kotlin file anyway).
abstract class StageCoverageSource : DefaultTask() {
    @get:InputFile
    abstract val source: RegularFileProperty

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun stage() {
        val target = outputDir.get().asFile
        target.mkdirs()
        source.get().asFile.copyTo(target.resolve("Issue122Coverage.kt"), overwrite = true)
    }
}

val stageIssue122Coverage = tasks.register<StageCoverageSource>("stageIssue122Coverage") {
    source.set(issue122CoverageSource)
    outputDir.set(generatedCoverageDir)
}

androidComponents {
    onVariants { variant ->
        variant.androidTest?.sources?.kotlin?.addGeneratedSourceDirectory(
            stageIssue122Coverage,
            StageCoverageSource::outputDir,
        )
    }
}
