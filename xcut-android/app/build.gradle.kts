plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

val arpAssetsDir = layout.buildDirectory.dir("generated/arp-assets")

val buildArpBinaries = tasks.register("buildArpBinaries") {
    val ndkDir = android.sdkDirectory.resolve("ndk").listFiles()
        ?.maxByOrNull { it.name }?.absolutePath
        ?: error("Android NDK missing - run: sdkmanager \"ndk;27.0.12077973\"")
    outputs.dir(arpAssetsDir)
    doLast {
        val clangDir = "$ndkDir/toolchains/llvm/prebuilt/linux-x86_64/bin"
        val abis = mapOf(
            "arm64-v8a" to "aarch64-linux-android26-clang",
            "armeabi-v7a" to "armv7a-linux-androideabi26-clang",
            "x86_64" to "x86_64-linux-android26-clang",
        )
        abis.forEach { (abi, triple) ->
            val outDir = arpAssetsDir.get().dir(abi).asFile.apply { mkdirs() }
            exec {
                commandLine(
                    "$clangDir/$triple",
                    "-O2",
                    "-Wall",
                    "src/main/cpp/arp.c",
                    "-o", outDir.resolve("arp").absolutePath,
                )
            }
        }
    }
}

android {
    namespace = "com.drybrine.xcutandroid"
    compileSdk = 35

    defaultConfig {
        applicationId = "com.drybrine.xcutandroid"
        minSdk = 26
        targetSdk = 35
        versionCode = 2
        versionName = "1.1"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }

    kotlinOptions {
        jvmTarget = "17"
    }

    sourceSets["main"].assets.srcDir(arpAssetsDir)
}

tasks.matching { it.name.startsWith("merge") && it.name.endsWith("Assets") }
    .configureEach { dependsOn(buildArpBinaries) }

dependencies {
    implementation("dev.rikka.shizuku:api:13.1.5")
    implementation("dev.rikka.shizuku:provider:13.1.5")
    implementation("androidx.core:core-ktx:1.15.0")
    implementation("org.jetbrains.kotlinx:kotlinx-coroutines-android:1.9.0")
    implementation("org.lsposed.hiddenapibypass:hiddenapibypass:6.1")
}