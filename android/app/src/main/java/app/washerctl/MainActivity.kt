package app.washerctl

import android.annotation.SuppressLint
import android.app.Activity
import android.app.AlertDialog
import android.content.res.Configuration
import android.graphics.Color
import android.os.Build
import android.os.Bundle
import android.view.View
import android.view.WindowInsetsController
import android.view.WindowManager
import android.webkit.JavascriptInterface
import android.webkit.JsPromptResult
import android.webkit.JsResult
import android.webkit.WebChromeClient
import android.webkit.WebResourceRequest
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.EditText
import android.widget.FrameLayout
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import org.json.JSONObject

/**
 * Hosts the webapp's UI (assets/index.html) in a WebView. bridge.js forwards the page's
 * /api/... fetches to [Bridge.request], which runs them through [WasherApi] on a background thread.
 */
class MainActivity : Activity() {
    private lateinit var web: WebView
    private lateinit var api: WasherApi
    private val io: ExecutorService = Executors.newCachedThreadPool()

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        api = WasherApi(applicationContext)

        web = WebView(this)
        web.setBackgroundColor(Color.TRANSPARENT)
        web.settings.javaScriptEnabled = true
        web.settings.domStorageEnabled = true
        web.addJavascriptInterface(Bridge(), "WasherNative")
        web.webViewClient = object : WebViewClient() {
            // The UI never navigates; block anything that tries to.
            override fun shouldOverrideUrlLoading(view: WebView, request: WebResourceRequest) = true
        }
        web.webChromeClient = Dialogs()
        setContentView(FrameLayout(this).apply { addView(web) })
        styleSystemBars()  // needs the decor view, so after setContentView

        web.loadUrl("file:///android_asset/index.html")

        io.execute {
            if (api.autoDiscoverIfNeeded()) runOnUiThread { js("init()") }
        }
    }

    private fun isNight() =
        (resources.configuration.uiMode and Configuration.UI_MODE_NIGHT_MASK) == Configuration.UI_MODE_NIGHT_YES

    /** Match the bars to the page background (#f8f8fa light / #0a0a0f dark). */
    @Suppress("DEPRECATION")
    private fun styleSystemBars() {
        val night = isNight()
        val bg = if (night) 0xFF0A0A0F.toInt() else 0xFFF8F8FA.toInt()
        window.statusBarColor = bg
        window.navigationBarColor = bg
        if (Build.VERSION.SDK_INT >= 30) {
            val light = WindowInsetsController.APPEARANCE_LIGHT_STATUS_BARS or
                WindowInsetsController.APPEARANCE_LIGHT_NAVIGATION_BARS
            window.insetsController?.setSystemBarsAppearance(if (night) 0 else light, light)
        } else if (!night) {
            window.decorView.systemUiVisibility =
                View.SYSTEM_UI_FLAG_LIGHT_STATUS_BAR or View.SYSTEM_UI_FLAG_LIGHT_NAVIGATION_BAR
        }
    }

    private fun js(code: String) {
        if (!isDestroyed) web.evaluateJavascript(code, null)
    }

    override fun onResume() {
        super.onResume()
        web.onResume()
        web.resumeTimers()
        js("if (typeof pollStatus === 'function') pollStatus();")
    }

    override fun onPause() {
        // Stops the page's 5 s status polling while the app is in the background.
        web.onPause()
        web.pauseTimers()
        super.onPause()
    }

    override fun onDestroy() {
        io.shutdownNow()
        web.destroy()
        super.onDestroy()
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        // Back from the settings screen returns to the main view instead of leaving the app.
        web.evaluateJavascript(
            "(function(){var c=document.getElementById('viewConfig');" +
                "if(c&&c.classList.contains('active')){showView('main');return true}return false})()"
        ) { handled -> if (handled != "true") superBack() }
    }

    @Suppress("DEPRECATION")
    private fun superBack() = super.onBackPressed()

    inner class Bridge {
        @JavascriptInterface
        fun request(id: Int, method: String, path: String, body: String) {
            io.execute {
                val r = api.handle(method, path, body)
                val code = "window.__nativeResolve($id, ${r.status}, ${JSONObject.quote(r.body)})"
                runOnUiThread { js(code) }
            }
        }
    }

    /** Native dialogs for the page's confirm() / prompt() (stop cycle, name a favourite). */
    inner class Dialogs : WebChromeClient() {
        override fun onJsAlert(view: WebView, url: String?, message: String?, result: JsResult): Boolean {
            AlertDialog.Builder(this@MainActivity)
                .setMessage(message)
                .setPositiveButton(android.R.string.ok) { _, _ -> result.confirm() }
                .setOnCancelListener { result.cancel() }
                .show()
            return true
        }

        override fun onJsConfirm(view: WebView, url: String?, message: String?, result: JsResult): Boolean {
            AlertDialog.Builder(this@MainActivity)
                .setMessage(message)
                .setPositiveButton(android.R.string.ok) { _, _ -> result.confirm() }
                .setNegativeButton(android.R.string.cancel) { _, _ -> result.cancel() }
                .setOnCancelListener { result.cancel() }
                .show()
            return true
        }

        override fun onJsPrompt(
            view: WebView, url: String?, message: String?, defaultValue: String?, result: JsPromptResult,
        ): Boolean {
            val input = EditText(this@MainActivity).apply {
                setText(defaultValue ?: "")
                setSingleLine()
                selectAll()
            }
            val pad = (20 * resources.displayMetrics.density).toInt()
            val box = FrameLayout(this@MainActivity).apply {
                setPadding(pad, pad / 2, pad, 0)
                addView(input)
            }
            val dialog = AlertDialog.Builder(this@MainActivity)
                .setMessage(message)
                .setView(box)
                .setPositiveButton(android.R.string.ok) { _, _ -> result.confirm(input.text.toString()) }
                .setNegativeButton(android.R.string.cancel) { _, _ -> result.cancel() }
                .setOnCancelListener { result.cancel() }
                .create()
            dialog.window?.setSoftInputMode(WindowManager.LayoutParams.SOFT_INPUT_STATE_VISIBLE)
            dialog.show()
            input.requestFocus()
            return true
        }
    }
}
