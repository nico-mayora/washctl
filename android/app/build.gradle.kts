plugins {
    id("com.android.application")
    id("org.jetbrains.kotlin.android")
}

android {
    namespace = "app.washerctl"
    compileSdk = 35

    defaultConfig {
        applicationId = "app.washerctl"
        minSdk = 26
        targetSdk = 35
        versionCode = 2
        versionName = "1.1"
    }

    buildTypes {
        release {
            isMinifyEnabled = false
            // Personal sideloaded app: sign with the local debug key so the
            // release APK installs without setting up a keystore.
            signingConfig = signingConfigs.getByName("debug")
        }
    }

    compileOptions {
        sourceCompatibility = JavaVersion.VERSION_17
        targetCompatibility = JavaVersion.VERSION_17
    }
    kotlinOptions {
        jvmTarget = "17"
    }
}

dependencies {
    testImplementation("junit:junit:4.13.2")
    // Android's org.json is a stub in local unit tests; use the real one.
    testImplementation("org.json:json:20240303")
}

/**
 * Copies the web UI and data files from ../../web into the APK's assets, so the
 * webapp stays the single source for the UI and programme data.
 * index.html gets a <script src="bridge.js"> tag injected, which routes its
 * /api/... calls to the Kotlin backend instead of the Python server.
 * config.json (washer IP/key/MAC) is optional and only used to seed first launch.
 */
abstract class BundleWebAssets : DefaultTask() {
    @get:InputFiles
    @get:PathSensitive(PathSensitivity.NAME_ONLY)
    abstract val webFiles: ConfigurableFileCollection

    @get:OutputDirectory
    abstract val outputDir: DirectoryProperty

    @TaskAction
    fun run() {
        val out = outputDir.get().asFile
        out.deleteRecursively()
        out.mkdirs()
        for (f in webFiles.files.filter { it.isFile }) {
            if (f.name == "index.html") {
                val html = f.readText()
                if (!html.contains("<head>")) throw GradleException("index.html has no <head> tag to inject bridge.js into")
                out.resolve(f.name).writeText(html.replaceFirst("<head>", "<head>\n<script src=\"bridge.js\"></script>"))
            } else {
                f.copyTo(out.resolve(f.name), overwrite = true)
            }
        }
    }
}

val webDir = rootProject.layout.projectDirectory.dir("../web")
// Your washer's data (written by bootstrap.py / the web app) is only bundled when asked for,
// with -PwithLocalData, so a normal build is always safe to share.
val withLocalData = providers.gradleProperty("withLocalData").isPresent
val bundleWebAssets = tasks.register<BundleWebAssets>("bundleWebAssets") {
    webFiles.from(webDir.file("static/index.html"), webDir.file("programmes.json"))
    if (withLocalData) {
        webFiles.from(
            webDir.file("my_programmes.json"),  // your washer's programme list
            webDir.file("favourites.json"),
            webDir.file("config.json"),         // IP, encryption key, MAC
        )
    }
}

androidComponents {
    onVariants { variant ->
        variant.sources.assets?.addGeneratedSourceDirectory(bundleWebAssets, BundleWebAssets::outputDir)
    }
}
