package com.dastyab.app

import android.annotation.SuppressLint
import android.app.AlertDialog
import android.content.BroadcastReceiver
import android.content.ClipData
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.Bitmap
import android.graphics.Color
import android.graphics.Typeface
import android.graphics.drawable.GradientDrawable
import android.net.Uri
import android.os.Build
import android.os.Bundle
import android.text.TextUtils
import android.view.Gravity
import android.view.View
import android.view.ViewGroup
import android.webkit.CookieManager
import android.webkit.WebChromeClient
import android.webkit.WebResourceError
import android.webkit.WebResourceRequest
import android.webkit.WebSettings
import android.webkit.WebView
import android.webkit.WebViewClient
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.FrameLayout
import android.widget.HorizontalScrollView
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.TextView
import android.widget.Toast
import androidx.webkit.ProfileStore
import androidx.webkit.ProxyConfig
import androidx.webkit.ProxyController
import androidx.webkit.WebViewCompat
import androidx.webkit.WebViewFeature
import java.util.concurrent.Executor
import kotlin.concurrent.thread

/**
 * InAppBrowserActivity — Modern Multi-Profile WebView browser for Google AI Studio & Google Flow.
 *
 * Key capabilities:
 *  • Multiple isolated Google Account profiles (`BrowserProfileStore`):
 *    Uses Chromium `WebViewFeature.MULTI_PROFILE` (`ProfileStore` + `WebViewCompat.setProfile`) when
 *    supported, keeping Google login cookies, localStorage, IndexedDB, and site state strictly isolated
 *    across profiles while letting you switch between accounts in 1 tap. Automatically falls back to
 *    per-profile encrypted/private cookie-jar snapshots on older System WebViews (API 24+).
 *  • Modern Omnibar + active account monogram pill + scrollable quick-switch account strip +
 *    floating bottom action dock + smooth profile cross-fade animations.
 *  • Per-app `ProxyController` local proxy bridge override + Brutal Anti-Geoblock JS shield +
 *    live exit IP/country indicator + automated Geo-Block Auto-Chain recovery.
 */
class InAppBrowserActivity : DastyabActivity() {

    companion object {
        const val EXTRA_URL = "extra_browser_url"
        const val EXTRA_TITLE = "extra_browser_title"
        const val EXTRA_PROFILE_ID = "extra_browser_profile_id"
        private const val MAX_WARM_WEBVIEWS = 4

        fun launch(context: Context, title: String, url: String) {
            launch(context, title, url, null)
        }

        fun launch(context: Context, title: String, url: String, profileId: String?) {
            val intent = Intent(context, InAppBrowserActivity::class.java).apply {
                putExtra(EXTRA_TITLE, title)
                putExtra(EXTRA_URL, url)
                if (!profileId.isNullOrBlank()) {
                    putExtra(EXTRA_PROFILE_ID, profileId)
                }
            }
            context.startActivity(intent)
        }
    }

    private lateinit var webViewContainer: FrameLayout
    private lateinit var progress: ProgressBar
    private lateinit var tvTitle: TextView
    private lateinit var tvUrlSubtitle: TextView
    private lateinit var tvRouteStatus: TextView
    private lateinit var vpnDot: View
    private lateinit var btnAutoFix: Button
    private lateinit var btnBack: Button
    private lateinit var btnForward: Button
    private lateinit var btnProfilePill: LinearLayout
    private lateinit var tvActiveProfileBadge: TextView
    private lateinit var tvActiveProfileName: TextView
    private lateinit var profileRailScroll: HorizontalScrollView
    private lateinit var profileRail: LinearLayout
    private lateinit var omnibarCard: LinearLayout

    private lateinit var profileState: BrowserProfileStore.BrowserProfileState
    private val multiProfileNative: Boolean by lazy {
        runCatching { WebViewFeature.isFeatureSupported(WebViewFeature.MULTI_PROFILE) }.getOrDefault(false)
    }
    private val profileWebViews = LinkedHashMap<String, WebView>()
    private var currentWebView: WebView? = null

    private var initialUrl: String = CommandCompat.AISTUDIO_URL
    private var receiverRegistered = false
    private var lastDomAlertKey: String = ""
    private val failedEgressIps = java.util.Collections.synchronizedSet(LinkedHashSet<String>())
    private val failedChainSpecs = java.util.Collections.synchronizedSet(LinkedHashSet<String>())
    @Volatile private var currentBannerEgressIp: String? = null
    @Volatile private var currentBannerCountryCode: String = "US"
    @Volatile private var currentRouteChainSpec: String = ""
    private val autoChainInFlight = java.util.concurrent.atomic.AtomicBoolean(false)
    private val mainExecutor = Executor { runnable -> runOnUiThread(runnable) }

    private val stateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            refreshRouteAndIndicator()
        }
    }

    @SuppressLint("SetJavaScriptEnabled")
    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        val title = intent.getStringExtra(EXTRA_TITLE) ?: getString(R.string.browser_default_aistudio)
        initialUrl = intent.getStringExtra(EXTRA_URL) ?: CommandCompat.AISTUDIO_URL

        try {
            setContentView(R.layout.activity_in_app_browser)
            webViewContainer = findViewById(R.id.browserWebViewContainer)
            progress = findViewById(R.id.browserProgress)
            tvTitle = findViewById(R.id.tvBrowserTitle)
            tvUrlSubtitle = findViewById(R.id.tvBrowserUrlSubtitle)
            tvRouteStatus = findViewById(R.id.tvBrowserRouteStatus)
            vpnDot = findViewById(R.id.browserVpnDot)
            btnAutoFix = findViewById(R.id.btnBrowserAutoFix)
            btnBack = findViewById(R.id.btnBrowserBack)
            btnForward = findViewById(R.id.btnBrowserForward)
            btnProfilePill = findViewById(R.id.btnBrowserProfilePill)
            tvActiveProfileBadge = findViewById(R.id.tvActiveProfileBadge)
            tvActiveProfileName = findViewById(R.id.tvActiveProfileName)
            profileRailScroll = findViewById(R.id.browserProfileRailScroll)
            profileRail = findViewById(R.id.browserProfileRail)
            omnibarCard = findViewById(R.id.browserOmnibarCard)

            tvTitle.text = title
            tvUrlSubtitle.text = BrowserProfileStore.formatHostForOmnibar(initialUrl)

            profileState = BrowserProfileStore.load(this, initialUrl)
            intent.getStringExtra(EXTRA_PROFILE_ID)?.let { requestedId ->
                val switched = BrowserProfileStore.switchProfile(profileState, requestedId)
                if (switched != profileState) {
                    profileState = switched
                    BrowserProfileStore.save(this, profileState)
                }
            }

            wireControls()
            renderProfileChrome()
            registerStateReceivers()

            // Mount the active profile's WebView and load initial URL with current route proxy.
            switchToProfile(
                targetProfile = profileState.activeProfile(),
                overrideUrl = initialUrl,
                isInitialMount = true
            )
        } catch (t: Throwable) {
            DastyabLogger.e("InAppBrowser", t, "WebView unavailable; falling back to external browser")
            val opened = UiSafety.safeStartActivity(this, Intent(Intent.ACTION_VIEW, Uri.parse(initialUrl)))
            Toast.makeText(
                this,
                if (opened) getString(R.string.browser_webview_fallback) else getString(R.string.aistudio_no_browser),
                Toast.LENGTH_LONG
            ).show()
            finish()
        }
    }

    private fun wireControls() {
        findViewById<Button>(R.id.btnBrowserClose).setOnClickListener { finish() }

        btnBack.setOnClickListener {
            val wv = currentWebView
            if (wv != null && wv.canGoBack()) wv.goBack() else finish()
        }
        btnForward.setOnClickListener {
            val wv = currentWebView
            if (wv != null && wv.canGoForward()) wv.goForward()
        }
        findViewById<Button>(R.id.btnBrowserReload).setOnClickListener {
            lastDomAlertKey = ""
            currentWebView?.reload()
        }
        btnAutoFix.setOnClickListener {
            val target = GeoBypassEngine.TargetService.fromUrl(currentOrInitialUrl())
            autoChainCurrentService(target)
        }
        findViewById<Button>(R.id.btnBrowserMore).setOnClickListener {
            showToolsMenuDialog()
        }

        btnProfilePill.setOnClickListener { showProfileManagerDialog() }
        DastyabMotion.attachPressSpring(btnProfilePill)

        omnibarCard.setOnClickListener { showOmnibarNavigateDialog() }
        DastyabMotion.attachPressSpring(omnibarCard)

        findViewById<Button>(R.id.btnBrowserProxyMode).setOnClickListener {
            GoogleAccessSheet.show(this, tvTitle.text.toString(), currentOrInitialUrl()) {
                applyProxyAndLoad(currentOrInitialUrl())
            }
        }
        tvRouteStatus.setOnClickListener {
            GoogleAccessSheet.show(this, tvTitle.text.toString(), currentOrInitialUrl()) {
                applyProxyAndLoad(currentOrInitialUrl())
            }
        }
        findViewById<Button>(R.id.btnBrowserGeoCheck).setOnClickListener {
            GoogleAccessSheet.runLiveGeoCheckDialog(this, currentOrInitialUrl())
        }
        findViewById<Button>(R.id.btnBrowserSwitchSite).setOnClickListener {
            val cur = currentOrInitialUrl()
            val nextUrl = if (cur.contains("flow.google.com", ignoreCase = true)) {
                CommandCompat.AISTUDIO_URL
            } else {
                CommandCompat.FLOW_URL
            }
            val nextTitle = if (nextUrl == CommandCompat.AISTUDIO_URL) {
                getString(R.string.browser_default_aistudio)
            } else {
                getString(R.string.browser_default_flow)
            }
            initialUrl = nextUrl
            tvTitle.text = nextTitle
            tvUrlSubtitle.text = BrowserProfileStore.formatHostForOmnibar(nextUrl)
            lastDomAlertKey = ""
            applyProxyAndLoad(nextUrl)
        }
    }

    // ── Multi-Profile WebView Engine ────────────────────────────────────────

    @SuppressLint("SetJavaScriptEnabled")
    private fun obtainOrCreateWebView(profile: BrowserProfileStore.BrowserProfile): WebView {
        if (multiProfileNative) {
            profileWebViews[profile.id]?.let { existing ->
                // Touch LRU position
                profileWebViews.remove(profile.id)
                profileWebViews[profile.id] = existing
                applyProfileSettingsToWebView(existing, profile)
                return existing
            }
            // Evict oldest inactive WebView if pool exceeds limit
            if (profileWebViews.size >= MAX_WARM_WEBVIEWS) {
                val oldestKey = profileWebViews.keys.firstOrNull { it != profileState.activeProfileId }
                if (oldestKey != null) {
                    val evicted = profileWebViews.remove(oldestKey)
                    evicted?.let { destroyWebViewInstance(it) }
                }
            }
        } else {
            // Single shared engine mode: reuse existing WebView if present
            currentWebView?.let { existing ->
                applyProfileSettingsToWebView(existing, profile)
                return existing
            }
        }

        val wv = WebView(this)
        wv.layoutParams = FrameLayout.LayoutParams(
            ViewGroup.LayoutParams.MATCH_PARENT,
            ViewGroup.LayoutParams.MATCH_PARENT
        )

        if (multiProfileNative) {
            // Must assign Chromium profile BEFORE any navigation or JS evaluation!
            runCatching {
                ProfileStore.getInstance().getOrCreateProfile(profile.webkitName)
                WebViewCompat.setProfile(wv, profile.webkitName)
            }.onFailure { err ->
                DastyabLogger.w("InAppBrowser", "setProfile(${profile.webkitName}) fallback: %s", err.message ?: "")
            }
        }

        configureWebView(wv, profile)
        if (multiProfileNative) {
            profileWebViews[profile.id] = wv
        }
        return wv
    }

    @SuppressLint("SetJavaScriptEnabled")
    private fun configureWebView(wv: WebView, profile: BrowserProfileStore.BrowserProfile) {
        val settings = wv.settings
        settings.javaScriptEnabled = true
        settings.domStorageEnabled = true
        settings.databaseEnabled = true
        settings.loadWithOverviewMode = true
        settings.useWideViewPort = true
        settings.builtInZoomControls = true
        settings.displayZoomControls = false
        settings.mixedContentMode = WebSettings.MIXED_CONTENT_COMPATIBILITY_MODE
        applyProfileSettingsToWebView(wv, profile)

        runCatching {
            if (multiProfileNative) {
                val p = ProfileStore.getInstance().getProfile(profile.webkitName)
                val cm = p?.cookieManager ?: CookieManager.getInstance()
                cm.setAcceptCookie(true)
                cm.setAcceptThirdPartyCookies(wv, true)
            } else {
                val cm = CookieManager.getInstance()
                cm.setAcceptCookie(true)
                cm.setAcceptThirdPartyCookies(wv, true)
            }
        }

        wv.webChromeClient = object : WebChromeClient() {
            override fun onProgressChanged(view: WebView?, newProgress: Int) {
                if (!UiSafety.isActivityAlive(this@InAppBrowserActivity) || view !== currentWebView) return
                progress.progress = newProgress
                progress.visibility = if (newProgress in 1..99) View.VISIBLE else View.GONE
            }

            override fun onReceivedTitle(view: WebView?, pageTitle: String?) {
                if (!UiSafety.isActivityAlive(this@InAppBrowserActivity) || view !== currentWebView) return
                if (!pageTitle.isNullOrBlank()) {
                    tvTitle.text = pageTitle
                }
            }
        }

        wv.webViewClient = object : WebViewClient() {
            override fun onPageStarted(view: WebView?, url: String?, favicon: Bitmap?) {
                if (!UiSafety.isActivityAlive(this@InAppBrowserActivity)) return
                if (view === currentWebView) {
                    progress.visibility = View.VISIBLE
                    tvUrlSubtitle.text = BrowserProfileStore.formatHostForOmnibar(url)
                    updateNavButtonsState()
                }
                injectAntiLeakShield(view)
                checkUnsupportedRedirect(url)
            }

            override fun onPageFinished(view: WebView?, url: String?) {
                if (!UiSafety.isActivityAlive(this@InAppBrowserActivity)) return
                val resolvedUrl = view?.url ?: url
                if (view === currentWebView) {
                    progress.visibility = View.GONE
                    tvUrlSubtitle.text = BrowserProfileStore.formatHostForOmnibar(resolvedUrl)
                    updateNavButtonsState()
                    val active = profileState.activeProfile()
                    if (!resolvedUrl.isNullOrBlank() && resolvedUrl.startsWith("http")) {
                        profileState = BrowserProfileStore.updateLastUrl(profileState, active.id, resolvedUrl)
                        BrowserProfileStore.save(this@InAppBrowserActivity, profileState)
                        BrowserProfileStore.snapshotLegacyCookies(this@InAppBrowserActivity, active.id, resolvedUrl)
                    }
                }
                injectAntiLeakShield(view)
                checkUnsupportedRedirect(resolvedUrl)
                inspectWebViewDomGeo(resolvedUrl, view)
                detectSignedInGoogleEmail(view)
                view?.postDelayed({
                    if (UiSafety.isActivityAlive(this@InAppBrowserActivity) && view === currentWebView) {
                        injectAntiLeakShield(view)
                        inspectWebViewDomGeo(view.url ?: resolvedUrl, view)
                        detectSignedInGoogleEmail(view)
                    }
                }, 1500L)
                view?.postDelayed({
                    if (UiSafety.isActivityAlive(this@InAppBrowserActivity) && view === currentWebView) {
                        inspectWebViewDomGeo(view.url ?: resolvedUrl, view)
                    }
                }, 3500L)
            }

            override fun onReceivedError(
                view: WebView?,
                request: WebResourceRequest?,
                error: WebResourceError?
            ) {
                if (request?.isForMainFrame == true &&
                    view === currentWebView &&
                    UiSafety.isActivityAlive(this@InAppBrowserActivity)
                ) {
                    Toast.makeText(
                        this@InAppBrowserActivity,
                        getString(R.string.browser_load_error_hint),
                        Toast.LENGTH_LONG
                    ).show()
                }
            }
        }
    }

    private fun applyProfileSettingsToWebView(
        wv: WebView,
        profile: BrowserProfileStore.BrowserProfile
    ) {
        val settings = wv.settings
        if (profile.desktopMode) {
            settings.userAgentString = BrutalAntiGeoblockEngine.CHROME_DESKTOP_UA
        } else {
            val defaultUa = runCatching { WebSettings.getDefaultUserAgent(this) }.getOrDefault("")
            val clean = defaultUa.replace("; wv)", ")").replace("Version/4.0 ", "")
            settings.userAgentString = if (clean.isNotBlank()) clean else BrutalAntiGeoblockEngine.CHROME_MOBILE_UA
        }
    }

    private fun switchToProfile(
        targetProfile: BrowserProfileStore.BrowserProfile,
        overrideUrl: String? = null,
        isInitialMount: Boolean = false
    ) {
        val previous = profileState.activeProfile()
        if (!isInitialMount && !multiProfileNative && previous.id != targetProfile.id) {
            BrowserProfileStore.snapshotLegacyCookies(this, previous.id, currentWebView?.url)
        }

        profileState = BrowserProfileStore.switchProfile(profileState, targetProfile.id)
        BrowserProfileStore.save(this, profileState)
        renderProfileChrome()
        lastDomAlertKey = ""

        val urlToShow = overrideUrl ?: targetProfile.lastUrl.ifBlank { initialUrl }

        if (multiProfileNative) {
            val isFreshWebView = !profileWebViews.containsKey(targetProfile.id)
            val nextView = obtainOrCreateWebView(targetProfile)
            mountWebViewWithTransition(nextView, animate = !isInitialMount)
            if (isFreshWebView || overrideUrl != null) {
                applyProxyAndLoad(urlToShow)
            } else {
                tvTitle.text = nextView.title?.takeIf { it.isNotBlank() } ?: getString(R.string.browser_default_aistudio)
                tvUrlSubtitle.text = BrowserProfileStore.formatHostForOmnibar(nextView.url ?: urlToShow)
                updateNavButtonsState()
                refreshRouteAndIndicator()
            }
        } else {
            val nextView = obtainOrCreateWebView(targetProfile)
            mountWebViewWithTransition(nextView, animate = !isInitialMount)
            if (isInitialMount && previous.id == targetProfile.id) {
                applyProxyAndLoad(urlToShow)
            } else {
                BrowserProfileStore.restoreLegacyCookies(this, targetProfile.id) {
                    if (!UiSafety.isActivityAlive(this)) return@restoreLegacyCookies
                    nextView.clearHistory()
                    applyProxyAndLoad(urlToShow, bypassCache = true)
                }
            }
        }

        if (!isInitialMount) {
            Toast.makeText(
                this,
                getString(R.string.browser_profile_switched, targetProfile.name),
                Toast.LENGTH_SHORT
            ).show()
        }
    }

    private fun mountWebViewWithTransition(wv: WebView, animate: Boolean) {
        val prev = currentWebView
        if (prev !== wv) {
            if (wv.parent !== webViewContainer) {
                (wv.parent as? ViewGroup)?.removeView(wv)
                webViewContainer.addView(wv)
            }
            for (i in 0 until webViewContainer.childCount) {
                val child = webViewContainer.getChildAt(i)
                child.visibility = if (child === wv) View.VISIBLE else View.GONE
            }
            currentWebView = wv
        }
        wv.visibility = View.VISIBLE
        if (animate && DastyabMotion.areAnimationsEnabled(this)) {
            wv.animate().cancel()
            wv.alpha = 0.25f
            wv.translationY = 10f * resources.displayMetrics.density
            wv.animate()
                .alpha(1f)
                .translationY(0f)
                .setDuration(220L)
                .start()
        } else {
            wv.alpha = 1f
            wv.translationY = 0f
        }
        updateNavButtonsState()
    }

    private fun destroyWebViewInstance(wv: WebView) {
        runCatching {
            (wv.parent as? ViewGroup)?.removeView(wv)
            wv.stopLoading()
            wv.loadUrl("about:blank")
            wv.clearHistory()
            wv.removeAllViews()
            wv.destroy()
        }
    }

    // ── Modern Profile Chrome & Dialogs ─────────────────────────────────────

    private fun renderProfileChrome() {
        val active = profileState.activeProfile()
        val density = resources.displayMetrics.density
        val activeColor = safeColor(active.colorHex, ThemeManager.resolveColor(this, R.attr.dastyabAccent, R.color.colorAccent))

        tvActiveProfileBadge.text = BrowserProfileStore.avatarInitial(active)
        tvActiveProfileBadge.setTextColor(contrastTextFor(activeColor))
        tvActiveProfileBadge.background = GradientDrawable().apply {
            shape = GradientDrawable.OVAL
            setColor(activeColor)
        }
        tvActiveProfileName.text = BrowserProfileStore.chipLabel(active)

        val accent = ThemeManager.resolveColor(this, R.attr.dastyabAccent, R.color.colorAccent)
        val textPrimary = ThemeManager.resolveColor(this, R.attr.dastyabTextPrimary, R.color.colorTextPrimary)
        val textSecondary = ThemeManager.resolveColor(this, R.attr.dastyabTextSecondary, R.color.colorTextSecondary)
        val chipBg = ThemeManager.resolveColor(this, R.attr.dastyabSurfaceElevated, R.color.colorSurfaceElevated)
        val chipActiveBg = ThemeManager.resolveColor(this, R.attr.dastyabAccentSoft, R.color.colorChipBg)
        val borderColor = ThemeManager.resolveColor(this, R.attr.dastyabCardBorder, R.color.colorCardBorder)

        profileRail.removeAllViews()
        var activeChipView: View? = null

        for (p in profileState.profiles) {
            val isSelected = p.id == active.id
            val pColor = safeColor(p.colorHex, accent)

            val chip = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                val hPad = (9 * density).toInt()
                val vPad = (5 * density).toInt()
                setPadding(hPad, vPad, (11 * density).toInt(), vPad)
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.WRAP_CONTENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply {
                    marginEnd = (6 * density).toInt()
                }
                background = GradientDrawable().apply {
                    shape = GradientDrawable.RECTANGLE
                    cornerRadius = 18f * density
                    setColor(if (isSelected) chipActiveBg else chipBg)
                    setStroke(
                        ((if (isSelected) 1.5f else 1f) * density).toInt().coerceAtLeast(1),
                        if (isSelected) pColor else borderColor
                    )
                }
            }

            val avatar = TextView(this).apply {
                val size = (20 * density).toInt()
                layoutParams = LinearLayout.LayoutParams(size, size).apply {
                    marginEnd = (6 * density).toInt()
                }
                gravity = Gravity.CENTER
                text = BrowserProfileStore.avatarInitial(p)
                textSize = 10f
                typeface = Typeface.DEFAULT_BOLD
                setTextColor(contrastTextFor(pColor))
                background = GradientDrawable().apply {
                    shape = GradientDrawable.OVAL
                    setColor(pColor)
                }
            }

            val label = TextView(this).apply {
                text = BrowserProfileStore.chipLabel(p)
                textSize = 11.5f
                typeface = if (isSelected) Typeface.DEFAULT_BOLD else Typeface.DEFAULT
                setTextColor(if (isSelected) textPrimary else textSecondary)
                maxLines = 1
                ellipsize = TextUtils.TruncateAt.END
            }

            chip.addView(avatar)
            chip.addView(label)
            chip.setOnClickListener {
                if (p.id == profileState.activeProfileId) {
                    showProfileManagerDialog()
                } else {
                    switchToProfile(p)
                }
            }
            chip.setOnLongClickListener {
                showSingleProfileActionsDialog(p)
                true
            }
            DastyabMotion.attachPressSpring(chip)
            profileRail.addView(chip)
            if (isSelected) activeChipView = chip
        }

        // "+ Account" quick-create pill at end of rail
        val addChip = TextView(this).apply {
            text = getString(R.string.browser_profile_add_chip)
            textSize = 11.5f
            typeface = Typeface.DEFAULT_BOLD
            setTextColor(accent)
            setPadding((11 * density).toInt(), (5 * density).toInt(), (11 * density).toInt(), (5 * density).toInt())
            background = GradientDrawable().apply {
                shape = GradientDrawable.RECTANGLE
                cornerRadius = 18f * density
                setColor(Color.TRANSPARENT)
                setStroke((1f * density).toInt().coerceAtLeast(1), accent)
            }
            setOnClickListener { showCreateProfileDialog() }
        }
        DastyabMotion.attachPressSpring(addChip)
        profileRail.addView(addChip)

        activeChipView?.let { target ->
            profileRailScroll.post {
                val x = (target.left - (24 * density).toInt()).coerceAtLeast(0)
                profileRailScroll.smoothScrollTo(x, 0)
            }
        }
    }

    private fun showProfileManagerDialog() {
        val density = resources.displayMetrics.density
        val textPrimary = ThemeManager.resolveColor(this, R.attr.dastyabTextPrimary, R.color.colorTextPrimary)
        val textSecondary = ThemeManager.resolveColor(this, R.attr.dastyabTextSecondary, R.color.colorTextSecondary)
        val accent = ThemeManager.resolveColor(this, R.attr.dastyabAccent, R.color.colorAccent)
        val cardBg = ThemeManager.resolveColor(this, R.attr.dastyabSurfaceElevated, R.color.colorSurfaceElevated)
        val activeBg = ThemeManager.resolveColor(this, R.attr.dastyabAccentSoft, R.color.colorChipBg)
        val borderColor = ThemeManager.resolveColor(this, R.attr.dastyabCardBorder, R.color.colorCardBorder)

        val root = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val p = (16 * density).toInt()
            setPadding(p, (10 * density).toInt(), p, (6 * density).toInt())
        }

        val info = TextView(this).apply {
            text = if (multiProfileNative) {
                getString(R.string.browser_profile_isolation_native)
            } else {
                getString(R.string.browser_profile_isolation_jar)
            }
            textSize = 12f
            setTextColor(textSecondary)
            setPadding(0, 0, 0, (12 * density).toInt())
        }
        root.addView(info)

        var dialogRef: AlertDialog? = null
        val activeId = profileState.activeProfileId

        for (p in profileState.profiles) {
            val isSelected = p.id == activeId
            val pColor = safeColor(p.colorHex, accent)

            val row = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
                gravity = Gravity.CENTER_VERTICAL
                setPadding((12 * density).toInt(), (10 * density).toInt(), (10 * density).toInt(), (10 * density).toInt())
                layoutParams = LinearLayout.LayoutParams(
                    ViewGroup.LayoutParams.MATCH_PARENT,
                    ViewGroup.LayoutParams.WRAP_CONTENT
                ).apply {
                    bottomMargin = (8 * density).toInt()
                }
                background = GradientDrawable().apply {
                    shape = GradientDrawable.RECTANGLE
                    cornerRadius = 14f * density
                    setColor(if (isSelected) activeBg else cardBg)
                    setStroke(
                        ((if (isSelected) 1.5f else 1f) * density).toInt().coerceAtLeast(1),
                        if (isSelected) pColor else borderColor
                    )
                }
            }

            val badge = TextView(this).apply {
                val s = (34 * density).toInt()
                layoutParams = LinearLayout.LayoutParams(s, s).apply {
                    marginEnd = (12 * density).toInt()
                }
                gravity = Gravity.CENTER
                text = BrowserProfileStore.avatarInitial(p)
                textSize = 14f
                typeface = Typeface.DEFAULT_BOLD
                setTextColor(contrastTextFor(pColor))
                background = GradientDrawable().apply {
                    shape = GradientDrawable.OVAL
                    setColor(pColor)
                }
            }

            val metaCol = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                layoutParams = LinearLayout.LayoutParams(0, ViewGroup.LayoutParams.WRAP_CONTENT, 1f)
            }
            val nameTv = TextView(this).apply {
                text = if (isSelected) "${p.name}  ✓" else p.name
                textSize = 14f
                typeface = Typeface.DEFAULT_BOLD
                setTextColor(textPrimary)
            }
            val subTv = TextView(this).apply {
                text = if (p.detectedEmail.isNotBlank()) {
                    p.detectedEmail
                } else {
                    BrowserProfileStore.formatHostForOmnibar(p.lastUrl)
                }
                textSize = 11.5f
                setTextColor(textSecondary)
                maxLines = 1
                ellipsize = TextUtils.TruncateAt.END
            }
            metaCol.addView(nameTv)
            metaCol.addView(subTv)

            val moreBtn = TextView(this).apply {
                text = "⋮"
                textSize = 18f
                typeface = Typeface.DEFAULT_BOLD
                setTextColor(textSecondary)
                setPadding((10 * density).toInt(), (4 * density).toInt(), (6 * density).toInt(), (4 * density).toInt())
                setOnClickListener {
                    dialogRef?.dismiss()
                    showSingleProfileActionsDialog(p)
                }
            }

            row.addView(badge)
            row.addView(metaCol)
            row.addView(moreBtn)
            row.setOnClickListener {
                dialogRef?.dismiss()
                if (!isSelected) {
                    switchToProfile(p)
                }
            }
            DastyabMotion.attachPressSpring(row)
            root.addView(row)
        }

        val builder = AlertDialog.Builder(this)
            .setTitle(getString(R.string.browser_profile_manager_title))
            .setView(root)
            .setPositiveButton(getString(R.string.browser_profile_new_btn)) { _, _ ->
                showCreateProfileDialog()
            }
            .setNeutralButton(getString(R.string.browser_profile_signin_btn)) { _, _ ->
                applyProxyAndLoad(BrowserProfileStore.GOOGLE_SIGNIN_CONTINUE_URL, bypassCache = true)
            }
            .setNegativeButton(android.R.string.cancel, null)

        dialogRef = UiSafety.safeShowDialog(this, builder)
    }

    private fun showCreateProfileDialog() {
        val density = resources.displayMetrics.density
        val defaultSuggestedColor = BrowserProfileStore.selectNextColor(profileState.profiles)
        var chosenColor = defaultSuggestedColor

        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            val p = (18 * density).toInt()
            setPadding(p, (12 * density).toInt(), p, (6 * density).toInt())
        }

        val input = EditText(this).apply {
            hint = getString(R.string.browser_profile_name_hint)
            setText("Account ${profileState.profiles.size + 1}")
            setSelection(text.length)
            setSingleLine(true)
        }
        container.addView(input)

        val swatchesRow = LinearLayout(this).apply {
            orientation = LinearLayout.HORIZONTAL
            gravity = Gravity.CENTER_VERTICAL
            setPadding(0, (12 * density).toInt(), 0, (10 * density).toInt())
        }
        val swatchViews = ArrayList<Pair<String, View>>()
        fun refreshSwatches() {
            for ((hex, v) in swatchViews) {
                val c = safeColor(hex, Color.YELLOW)
                val selected = hex.equals(chosenColor, ignoreCase = true)
                v.background = GradientDrawable().apply {
                    shape = GradientDrawable.OVAL
                    setColor(c)
                    if (selected) {
                        setStroke((3 * density).toInt().coerceAtLeast(2), Color.WHITE)
                    }
                }
                v.scaleX = if (selected) 1.15f else 1f
                v.scaleY = if (selected) 1.15f else 1f
            }
        }
        for (hex in BrowserProfileStore.PROFILE_COLORS) {
            val dot = View(this).apply {
                val size = (26 * density).toInt()
                layoutParams = LinearLayout.LayoutParams(size, size).apply {
                    marginEnd = (8 * density).toInt()
                }
                setOnClickListener {
                    chosenColor = hex
                    refreshSwatches()
                }
            }
            swatchViews.add(hex to dot)
            swatchesRow.addView(dot)
        }
        refreshSwatches()
        container.addView(swatchesRow)

        val cbSignIn = CheckBox(this).apply {
            text = getString(R.string.browser_profile_open_signin_after)
            isChecked = true
        }
        container.addView(cbSignIn)

        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(getString(R.string.browser_profile_create_title))
                .setView(container)
                .setPositiveButton(android.R.string.ok) { _, _ ->
                    val startUrl = if (cbSignIn.isChecked) {
                        BrowserProfileStore.GOOGLE_SIGNIN_CONTINUE_URL
                    } else {
                        currentOrInitialUrl()
                    }
                    val (nextState, created) = BrowserProfileStore.createProfile(
                        state = profileState,
                        rawName = input.text.toString(),
                        colorHex = chosenColor,
                        initialUrl = startUrl
                    )
                    if (!multiProfileNative) {
                        BrowserProfileStore.snapshotLegacyCookies(this, profileState.activeProfileId, currentWebView?.url)
                    }
                    profileState = nextState
                    BrowserProfileStore.save(this, profileState)
                    Toast.makeText(this, getString(R.string.browser_profile_created, created.name), Toast.LENGTH_SHORT).show()
                    switchToProfile(created, overrideUrl = startUrl, isInitialMount = false)
                }
                .setNegativeButton(android.R.string.cancel, null)
        )
    }

    private fun showSingleProfileActionsDialog(profile: BrowserProfileStore.BrowserProfile) {
        val options = arrayListOf(
            "Switch to ${profile.name}",
            "Rename Account",
            "Sign in with Google",
            "Clear Account Session Data"
        )
        if (profileState.profiles.size > 1) {
            options.add("Remove Account Profile")
        }

        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(
                    if (profile.detectedEmail.isNotBlank()) "${profile.name} (${profile.detectedEmail})" else profile.name
                )
                .setItems(options.toTypedArray()) { _, which ->
                    when (which) {
                        0 -> switchToProfile(profile)
                        1 -> showRenameProfileDialog(profile)
                        2 -> switchToProfile(profile, overrideUrl = BrowserProfileStore.GOOGLE_SIGNIN_CONTINUE_URL)
                        3 -> {
                            BrowserProfileStore.clearSessionData(this, profile)
                            if (profile.id == profileState.activeProfileId) {
                                currentWebView?.clearCache(true)
                                currentWebView?.loadUrl(BrowserProfileStore.GOOGLE_SIGNIN_CONTINUE_URL)
                            }
                            Toast.makeText(
                                this,
                                getString(R.string.browser_profile_session_cleared, profile.name),
                                Toast.LENGTH_SHORT
                            ).show()
                        }
                        4 -> confirmDeleteProfile(profile)
                    }
                }
        )
    }

    private fun showRenameProfileDialog(profile: BrowserProfileStore.BrowserProfile) {
        val input = EditText(this).apply {
            setText(profile.name)
            setSelection(text.length)
            setSingleLine(true)
        }
        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(getString(R.string.browser_profile_rename_title))
                .setView(input)
                .setPositiveButton(android.R.string.ok) { _, _ ->
                    profileState = BrowserProfileStore.renameProfile(profileState, profile.id, input.text.toString())
                    BrowserProfileStore.save(this, profileState)
                    renderProfileChrome()
                }
                .setNegativeButton(android.R.string.cancel, null)
        )
    }

    private fun confirmDeleteProfile(profile: BrowserProfileStore.BrowserProfile) {
        if (profileState.profiles.size <= 1) {
            Toast.makeText(this, getString(R.string.browser_profile_cannot_delete_last), Toast.LENGTH_SHORT).show()
            return
        }
        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(profile.name)
                .setMessage(getString(R.string.browser_profile_delete_confirm, profile.name))
                .setPositiveButton(android.R.string.ok) { _, _ ->
                    val deletingActive = profile.id == profileState.activeProfileId
                    val res = BrowserProfileStore.deleteProfile(profileState, profile.id)
                    if (res.removed == null) {
                        Toast.makeText(this, res.rejectedReason ?: getString(R.string.browser_profile_cannot_delete_last), Toast.LENGTH_SHORT).show()
                        return@setPositiveButton
                    }
                    // Destroy any live WebView bound to this profile before deleting its ProfileStore data
                    profileWebViews.remove(profile.id)?.let { doomed ->
                        if (doomed === currentWebView) currentWebView = null
                        destroyWebViewInstance(doomed)
                    }
                    BrowserProfileStore.deleteProfileStorage(this, profile)
                    profileState = res.state
                    BrowserProfileStore.save(this, profileState)
                    Toast.makeText(this, getString(R.string.browser_profile_deleted, profile.name), Toast.LENGTH_SHORT).show()
                    if (deletingActive) {
                        switchToProfile(profileState.activeProfile())
                    } else {
                        renderProfileChrome()
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
        )
    }

    private fun showOmnibarNavigateDialog() {
        val input = EditText(this).apply {
            hint = getString(R.string.browser_omnibar_hint)
            setText(currentOrInitialUrl())
            setSelection(text.length)
            setSingleLine(true)
        }
        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(getString(R.string.browser_omnibar_title))
                .setView(input)
                .setPositiveButton(android.R.string.ok) { _, _ ->
                    var url = input.text.toString().trim()
                    if (url.isNotEmpty() && !url.startsWith("http://") && !url.startsWith("https://")) {
                        url = "https://$url"
                    }
                    if (url.startsWith("http://") || url.startsWith("https://")) {
                        applyProxyAndLoad(url)
                    }
                }
                .setNeutralButton("AI Studio") { _, _ -> applyProxyAndLoad(CommandCompat.AISTUDIO_URL) }
                .setNegativeButton("Google Flow") { _, _ -> applyProxyAndLoad(CommandCompat.FLOW_URL) }
        )
    }

    private fun showToolsMenuDialog() {
        val active = profileState.activeProfile()
        val items = arrayOf(
            getString(R.string.browser_tool_profiles, profileState.profiles.size),
            getString(R.string.browser_tool_add_google),
            getString(if (active.desktopMode) R.string.browser_tool_desktop_on else R.string.browser_tool_desktop_off),
            getString(R.string.browser_tool_rotate),
            getString(R.string.browser_tool_dns_blackout),
            getString(R.string.browser_tool_open_chrome),
            getString(R.string.browser_tool_copy_url),
            getString(R.string.browser_tool_clear_profile)
        )
        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(getString(R.string.browser_tools_title))
                .setItems(items) { _, which ->
                    when (which) {
                        0 -> showProfileManagerDialog()
                        1 -> applyProxyAndLoad(BrowserProfileStore.GOOGLE_SIGNIN_CONTINUE_URL, bypassCache = true)
                        2 -> {
                            val nextDesktop = !active.desktopMode
                            profileState = BrowserProfileStore.updateDesktopMode(profileState, active.id, nextDesktop)
                            BrowserProfileStore.save(this, profileState)
                            currentWebView?.let { wv ->
                                applyProfileSettingsToWebView(wv, profileState.activeProfile())
                                wv.reload()
                            }
                            Toast.makeText(
                                this,
                                if (nextDesktop) "Switched to Desktop User-Agent" else "Switched to Mobile User-Agent",
                                Toast.LENGTH_SHORT
                            ).show()
                        }
                        3 -> {
                            BrutalAntiGeoblockEngine.enforceStrictBypass(this)
                            Toast.makeText(this, "Rotated VPN Layer & applied Brutal headers", Toast.LENGTH_SHORT).show()
                            currentWebView?.reload()
                        }
                        4 -> {
                            val settings = TunnelConfig.load(this)
                            val newMode = if (settings.mode == TunnelConfig.Mode.DNS_BLACKOUT) {
                                TunnelConfig.Mode.SMART
                            } else {
                                TunnelConfig.Mode.DNS_BLACKOUT
                            }
                            TunnelConfig.saveMode(this, newMode)
                            Toast.makeText(this, "Switched mode -> ${newMode.name}", Toast.LENGTH_SHORT).show()
                            applyProxyAndLoad(currentOrInitialUrl(), bypassCache = true)
                        }
                        5 -> {
                            val currentUrl = currentOrInitialUrl()
                            if (!UiSafety.safeStartActivity(this, Intent(Intent.ACTION_VIEW, Uri.parse(currentUrl)))) {
                                Toast.makeText(this, getString(R.string.aistudio_no_browser), Toast.LENGTH_SHORT).show()
                            }
                        }
                        6 -> {
                            val currentUrl = currentOrInitialUrl()
                            val cm = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                            cm?.setPrimaryClip(ClipData.newPlainText("DastYab URL", currentUrl))
                            Toast.makeText(this, getString(R.string.copied_to_clipboard), Toast.LENGTH_SHORT).show()
                        }
                        7 -> {
                            BrowserProfileStore.clearSessionData(this, active)
                            currentWebView?.clearCache(true)
                            applyProxyAndLoad(BrowserProfileStore.GOOGLE_SIGNIN_CONTINUE_URL, bypassCache = true)
                            Toast.makeText(
                                this,
                                getString(R.string.browser_profile_session_cleared, active.name),
                                Toast.LENGTH_SHORT
                            ).show()
                        }
                    }
                }
        )
    }

    private fun detectSignedInGoogleEmail(targetView: WebView?) {
        val wv = targetView ?: currentWebView ?: return
        if (!UiSafety.isActivityAlive(this) || wv !== currentWebView) return
        val activeId = profileState.activeProfileId
        val js = "(function(){try{" +
            "var els=document.querySelectorAll('a[aria-label*=\"@\"],button[aria-label*=\"@\"],div[data-email],span[data-email]');" +
            "for(var i=0;i<els.length;i++){" +
            "var v=els[i].getAttribute('data-email')||els[i].getAttribute('aria-label')||'';" +
            "var m=v.match(/[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\\.[A-Za-z]{2,}/);" +
            "if(m)return m[0];" +
            "}return null;}catch(e){return null;}})();"
        runCatching {
            wv.evaluateJavascript(js) { raw ->
                if (!UiSafety.isActivityAlive(this) || raw.isNullOrBlank() || raw == "null") return@evaluateJavascript
                val email = raw.trim().trim('"')
                if (email.contains("@") && email != "null") {
                    val before = profileState.profiles.firstOrNull { it.id == activeId }?.detectedEmail.orEmpty()
                    if (before != email) {
                        profileState = BrowserProfileStore.updateDetectedEmail(profileState, activeId, email)
                        BrowserProfileStore.save(this, profileState)
                        renderProfileChrome()
                    }
                }
            }
        }
    }

    private fun updateNavButtonsState() {
        val wv = currentWebView
        if (this::btnBack.isInitialized) {
            val canBack = wv?.canGoBack() == true
            btnBack.alpha = if (canBack) 1.0f else 0.55f
        }
        if (this::btnForward.isInitialized) {
            val canFwd = wv?.canGoForward() == true
            btnForward.isEnabled = canFwd
            btnForward.alpha = if (canFwd) 1.0f else 0.45f
        }
    }

    private fun safeColor(hex: String, fallback: Int): Int {
        return runCatching { Color.parseColor(hex) }.getOrDefault(fallback)
    }

    private fun contrastTextFor(bgColor: Int): Int {
        val lum = (0.299 * Color.red(bgColor) + 0.587 * Color.green(bgColor) + 0.114 * Color.blue(bgColor)) / 255.0
        return if (lum > 0.58) 0xFF140F06.toInt() else 0xFFFFFFFF.toInt()
    }

    // ── Geo-Bypass, Anti-Leak & Proxy Override ──────────────────────────────

    private fun injectAntiLeakShield(targetView: WebView? = currentWebView) {
        val wv = targetView ?: return
        if (!UiSafety.isActivityAlive(this)) return
        val script = BrutalAntiGeoblockEngine.buildWebViewAntiLeakScript(currentBannerCountryCode)
        runCatching { wv.evaluateJavascript(script, null) }
    }

    private fun currentOrInitialUrl(): String =
        currentWebView?.url?.takeIf { it.startsWith("http") } ?: initialUrl

    private fun checkUnsupportedRedirect(url: String?) {
        if (url.isNullOrBlank()) return
        val target = GeoBypassEngine.TargetService.fromUrl(url)
        val blocked = when (target) {
            GeoBypassEngine.TargetService.GOOGLE_FLOW ->
                GeoBypassEngine.isFlowUnsupportedResponse(200, url, "")
            GeoBypassEngine.TargetService.AI_STUDIO ->
                GeoBypassEngine.isAiStudioUnsupportedResponse(200, url, url, "")
        }
        if (blocked) {
            setBrowserHalo(StatusHaloView.HaloState.ERROR, R.drawable.status_dot_red)
            tvRouteStatus.text = getString(R.string.browser_geo_blocked)
            tvRouteStatus.setTextColor(ThemeManager.resolveColor(this, R.attr.dastyabStatusError, R.color.colorStatusError))
        }
    }

    private fun inspectWebViewDomGeo(urlHint: String?, targetView: WebView? = currentWebView) {
        val wv = targetView ?: currentWebView ?: return
        if (!UiSafety.isActivityAlive(this) || wv !== currentWebView) return
        val js = "(function(){try{return({href:location.href,text:(document.body&&document.body.innerText?document.body.innerText:'').slice(0,6000),html:(document.documentElement?document.documentElement.innerHTML:'').slice(0,8192)});}catch(e){return null;}})();"
        wv.evaluateJavascript(js) { raw ->
            if (!UiSafety.isActivityAlive(this) || raw.isNullOrBlank() || raw == "null") return@evaluateJavascript
            val obj = runCatching {
                val jsonText = if (raw.startsWith("\"")) org.json.JSONTokener(raw).nextValue() as? String ?: "" else raw
                org.json.JSONObject(jsonText)
            }.getOrNull() ?: return@evaluateJavascript

            val href = obj.optString("href", urlHint.orEmpty())
            val bodyText = obj.optString("text", "")
            val html = obj.optString("html", "")
            val combined = "$bodyText\n$html"
            val target = GeoBypassEngine.TargetService.fromUrl(href.ifBlank { urlHint })
            val reason = when (target) {
                GeoBypassEngine.TargetService.GOOGLE_FLOW -> when {
                    GeoBypassEngine.isFlowUnsupportedResponse(200, href, combined) ->
                        "Flow unsupported region / geo-restriction"
                    GeoBypassEngine.isFlowAccountGateResponse(combined) ->
                        "Flow account / country access gate"
                    else -> null
                }
                GeoBypassEngine.TargetService.AI_STUDIO -> when {
                    GeoBypassEngine.isAiStudioUnsupportedResponse(200, href, href, combined) ->
                        "AI Studio unsupported region / geo-restriction"
                    else -> null
                }
            } ?: return@evaluateJavascript

            setBrowserHalo(StatusHaloView.HaloState.ERROR, R.drawable.status_dot_red)
            tvRouteStatus.text = getString(R.string.browser_geo_blocked)
            tvRouteStatus.setTextColor(ThemeManager.resolveColor(this, R.attr.dastyabStatusError, R.color.colorStatusError))
            currentBannerEgressIp?.takeIf { it.isNotBlank() }?.let { failedEgressIps.add(it) }
            currentRouteChainSpec.takeIf { it.isNotBlank() }?.let { failedChainSpecs.add(it) }

            val key = "${target.key}:${href.substringBefore('?')}"
            if (key == lastDomAlertKey || autoChainInFlight.get()) return@evaluateJavascript
            lastDomAlertKey = key

            UiSafety.safeShowDialog(
                this,
                AlertDialog.Builder(this)
                    .setTitle(getString(R.string.browser_dom_geo_blocked_title, target.displayName))
                    .setMessage(getString(R.string.browser_dom_geo_blocked_msg, reason, target.displayName))
                    .setPositiveButton(getString(R.string.browser_btn_auto_chain)) { _, _ ->
                        autoChainCurrentService(target)
                    }
                    .setNeutralButton(getString(R.string.access_sheet_switch_route_btn)) { _, _ ->
                        GoogleAccessSheet.show(this, target.displayName, href) {
                            applyProxyAndLoad(currentOrInitialUrl())
                        }
                    }
                    .setNegativeButton(android.R.string.cancel, null)
            )
        }
    }

    private fun autoChainCurrentService(target: GeoBypassEngine.TargetService) {
        if (!autoChainInFlight.compareAndSet(false, true)) return
        currentBannerEgressIp?.takeIf { it.isNotBlank() }?.let { failedEgressIps.add(it) }
        currentRouteChainSpec.takeIf { it.isNotBlank() }?.let { failedChainSpecs.add(it) }
        val excludedIpsSnapshot = synchronized(failedEgressIps) { failedEgressIps.toSet() }
        val excludedSpecsSnapshot = synchronized(failedChainSpecs) { failedChainSpecs.toSet() }

        if (this::btnAutoFix.isInitialized) btnAutoFix.isEnabled = false
        Toast.makeText(
            this,
            getString(R.string.browser_auto_chain_running, target.displayName),
            Toast.LENGTH_LONG
        ).show()
        setBrowserHalo(StatusHaloView.HaloState.CONNECTING, R.drawable.status_dot_orange)
        if (this::tvRouteStatus.isInitialized) {
            tvRouteStatus.text = getString(R.string.browser_auto_chain_running, target.displayName)
            tvRouteStatus.setTextColor(ThemeManager.resolveColor(this, R.attr.dastyabStatusWarning, R.color.colorStatusWarning))
        }
        thread(isDaemon = true, name = "dastyab-browser-autochain") {
            val isFlow = target == GeoBypassEngine.TargetService.GOOGLE_FLOW
            var warriorReport: FlowWarriorEngine.WarriorReport? = null
            var aiResult: GeoBypassEngine.ChainDiscoveryResult? = null
            try {
                if (isFlow) {
                    warriorReport = FlowWarriorEngine.runFlowWarriorAutopilot(
                        context = this,
                        excludedEgressIps = excludedIpsSnapshot,
                        excludedChainSpecs = excludedSpecsSnapshot,
                        excludeCurrentRoute = true
                    ) { step ->
                        runOnUiThread {
                            if (UiSafety.isActivityAlive(this) && this::tvRouteStatus.isInitialized) {
                                tvRouteStatus.text = step
                            }
                        }
                    }
                } else {
                    aiResult = BrutalAntiGeoblockEngine.unleashLionForAiStudio(
                        context = this,
                        excludedEgressIps = excludedIpsSnapshot,
                        excludeCurrentRoute = true,
                        excludedChainSpecs = excludedSpecsSnapshot
                    ) { step ->
                        runOnUiThread {
                            if (UiSafety.isActivityAlive(this) && this::tvRouteStatus.isInitialized) {
                                tvRouteStatus.text = step
                            }
                        }
                    }
                }
            } finally {
                autoChainInFlight.set(false)
            }
            val ok = warriorReport?.conquered ?: aiResult?.success ?: false
            val summaryText = warriorReport?.headline ?: aiResult?.summary ?: getString(R.string.browser_auto_chain_failed, target.displayName)
            val probeReport = warriorReport?.probeReport ?: aiResult?.report
            runOnUiThread {
                if (!UiSafety.isActivityAlive(this)) return@runOnUiThread
                if (this::btnAutoFix.isInitialized) btnAutoFix.isEnabled = true
                Toast.makeText(
                    this,
                    if (ok) summaryText else getString(R.string.browser_auto_chain_failed, target.displayName),
                    Toast.LENGTH_LONG
                ).show()
                if (ok) {
                    lastDomAlertKey = ""
                    clearServiceGeoCookiesAndCache(target)
                    val reloadTargetUrl = if (isFlow) CommandCompat.FLOW_URL else CommandCompat.AISTUDIO_URL
                    applyProxyAndLoad(reloadTargetUrl, bypassCache = true)
                } else {
                    probeReport?.egress?.ip?.takeIf { it.isNotBlank() }?.let { failedEgressIps.add(it) }
                    probeBannerEgress(GeoBypassEngine.resolveCurrentRoute(this, targetService = target), currentOrInitialUrl())
                    UiSafety.safeShowDialog(
                        this,
                        AlertDialog.Builder(this)
                            .setTitle(getString(R.string.browser_auto_chain_failed_title))
                            .setMessage("$summaryText\n\n${probeReport?.recommendation.orEmpty()}")
                            .setPositiveButton(getString(R.string.browser_btn_retry_chain)) { _, _ ->
                                autoChainCurrentService(target)
                            }
                            .setNeutralButton(getString(R.string.access_sheet_switch_route_btn)) { _, _ ->
                                GoogleAccessSheet.show(this, target.displayName, currentOrInitialUrl()) {
                                    applyProxyAndLoad(currentOrInitialUrl(), bypassCache = true)
                                }
                            }
                            .setNegativeButton(android.R.string.cancel, null)
                    )
                }
            }
        }
    }

    /** Clears cached geo-decision cookies & HTTP cache for AI Studio / Flow without logging out accounts. */
    private fun clearServiceGeoCookiesAndCache(target: GeoBypassEngine.TargetService) {
        runCatching {
            val active = profileState.activeProfile()
            val cm = if (multiProfileNative) {
                ProfileStore.getInstance().getProfile(active.webkitName)?.cookieManager
                    ?: CookieManager.getInstance()
            } else {
                CookieManager.getInstance()
            }
            val urls = if (target == GeoBypassEngine.TargetService.GOOGLE_FLOW) {
                listOf("https://flow.google.com", "https://labs.google")
            } else {
                listOf("https://aistudio.google.com", "https://ai.google.dev", "https://generativelanguage.googleapis.com")
            }
            for (u in urls) {
                val raw = cm.getCookie(u).orEmpty()
                for (pair in raw.split(';')) {
                    val name = pair.substringBefore('=').trim()
                    if (name.isNotEmpty()) {
                        cm.setCookie(u, "$name=; Max-Age=0; path=/")
                    }
                }
            }
            cm.flush()
        }
        currentWebView?.let { wv -> runCatching { wv.clearCache(true) } }
    }

    private fun applyProxyAndLoad(urlToLoad: String, bypassCache: Boolean = false) {
        thread(isDaemon = true, name = "dastyab-browser-route") {
            val settings = TunnelConfig.load(this)
            val targetService = GeoBypassEngine.TargetService.fromUrl(urlToLoad)
            var route = GeoBypassEngine.resolveCurrentRoute(this, settings, targetService)
            if (route.shouldStartLocalBridge) {
                LocalProxyService.startSafely(this, targetService.key)
                var waited = 0
                while (
                    (LocalProxyService.activePort() == null ||
                        LocalProxyService.activeChainSpec() != route.upstreamChainSpec) &&
                    waited < 2500
                ) {
                    try { Thread.sleep(50) } catch (_: InterruptedException) { break }
                    waited += 50
                }
                route = GeoBypassEngine.resolveCurrentRoute(this, settings, targetService)
            }

            currentRouteChainSpec = route.upstreamChainSpec
            runOnUiThread {
                if (!UiSafety.isActivityAlive(this)) return@runOnUiThread
                applyWebViewProxy(route.webViewHttpProxyPort) {
                    refreshRouteAndIndicator(route)
                    val wv = currentWebView
                    if (UiSafety.isActivityAlive(this) && wv != null) {
                        lastDomAlertKey = ""
                        tvUrlSubtitle.text = BrowserProfileStore.formatHostForOmnibar(urlToLoad)
                        if (bypassCache) {
                            wv.loadUrl(
                                urlToLoad,
                                BrutalAntiGeoblockEngine.getBrutalHeadersMap(currentBannerCountryCode)
                            )
                        } else {
                            wv.loadUrl(urlToLoad)
                        }
                    }
                    probeBannerEgress(route, urlToLoad)
                }
            }
        }
    }

    private fun applyWebViewProxy(httpProxyPort: Int?, onApplied: () -> Unit) {
        if (!WebViewFeature.isFeatureSupported(WebViewFeature.PROXY_OVERRIDE)) {
            if (httpProxyPort != null) {
                Toast.makeText(
                    this,
                    getString(R.string.browser_proxy_unsupported),
                    Toast.LENGTH_LONG
                ).show()
            }
            onApplied()
            return
        }

        val controller = ProxyController.getInstance()
        if (httpProxyPort != null) {
            val cfg = ProxyConfig.Builder()
                .addProxyRule("127.0.0.1:$httpProxyPort")
                .build()
            controller.setProxyOverride(cfg, mainExecutor, Runnable { onApplied() })
        } else {
            controller.clearProxyOverride(mainExecutor, Runnable { onApplied() })
        }
    }

    private fun probeBannerEgress(route: GeoBypassEngine.RouteResolution, targetUrl: String = initialUrl) {
        thread(isDaemon = true, name = "dastyab-browser-geo") {
            val report = GeoBypassEngine.runAccessProbe(route, timeoutMs = 4200)
            val target = route.targetService ?: GeoBypassEngine.TargetService.fromUrl(targetUrl)
            val ready = report.targetReady(target)
            currentRouteChainSpec = route.upstreamChainSpec
            report.egress?.let { eg ->
                if (eg.ip.isNotBlank()) {
                    currentBannerEgressIp = eg.ip
                    if (!ready) failedEgressIps.add(eg.ip)
                }
                if (eg.countryCode.length == 2) {
                    currentBannerCountryCode = eg.countryCode
                }
            }
            runOnUiThread {
                if (!UiSafety.isActivityAlive(this)) return@runOnUiThread
                injectAntiLeakShield()
                val egress = report.egress
                if (egress == null) {
                    setBrowserHalo(StatusHaloView.HaloState.WARNING, R.drawable.status_dot_orange)
                    tvRouteStatus.text = getString(R.string.browser_geo_check_hint, route.routeLabel)
                    tvRouteStatus.setTextColor(ThemeManager.resolveColor(this, R.attr.dastyabStatusWarning, R.color.colorStatusWarning))
                } else {
                    setBrowserHalo(
                        if (ready) StatusHaloView.HaloState.CONNECTED else StatusHaloView.HaloState.ERROR,
                        if (ready) R.drawable.status_dot_green else R.drawable.status_dot_red
                    )
                    tvRouteStatus.text = if (ready) {
                        BypassStateStore.markBypassed(this@InAppBrowserActivity, target.displayName, route.routeLabel)
                        getString(R.string.browser_banner_ready, target.displayName, route.routeLabel, egress.countryCode, egress.ip)
                    } else {
                        getString(R.string.browser_banner_blocked, target.displayName, route.routeLabel, egress.countryCode)
                    }
                    tvRouteStatus.setTextColor(
                        if (ready) ThemeManager.resolveColor(this, R.attr.dastyabStatusReady, R.color.colorStatusReady)
                        else ThemeManager.resolveColor(this, R.attr.dastyabStatusError, R.color.colorStatusError)
                    )
                }
            }
        }
    }

    override fun onResume() {
        super.onResume()
        currentWebView?.let { wv -> runCatching { wv.onResume() } }
        refreshRouteAndIndicator()
    }

    override fun onPause() {
        val active = if (this::profileState.isInitialized) profileState.activeProfile() else null
        if (active != null && !multiProfileNative) {
            BrowserProfileStore.snapshotLegacyCookies(this, active.id, currentWebView?.url)
        }
        currentWebView?.let { wv -> runCatching { wv.onPause() } }
        super.onPause()
    }

    private fun registerStateReceivers() {
        if (receiverRegistered) return
        val filter = IntentFilter().apply {
            addAction(DastyabVpnService.ACTION_STATE_CHANGED)
            addAction(LocalProxyService.ACTION_STATE_CHANGED)
        }
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(stateReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(stateReceiver, filter)
        }
        receiverRegistered = true
    }

    private fun setBrowserHalo(haloState: StatusHaloView.HaloState, fallbackDrawableRes: Int) {
        if (!this::vpnDot.isInitialized) return
        val halo = vpnDot as? StatusHaloView
        if (halo != null) {
            halo.setHaloState(haloState)
        } else {
            vpnDot.background = getDrawable(fallbackDrawableRes)
        }
    }

    private fun refreshRouteAndIndicator(precomputed: GeoBypassEngine.RouteResolution? = null) {
        if (!UiSafety.isActivityAlive(this) || !this::vpnDot.isInitialized) return
        try {
            val dastyabStatus = DastyabVpnService.getStatus()
            val externalVpn = NetworkUtils.hasActiveExternalVpn(this)
            val bridgeRunning = LocalProxyService.isRunning()
            when {
                dastyabStatus.state == DastyabVpnService.State.CONNECTED || externalVpn || bridgeRunning ->
                    setBrowserHalo(StatusHaloView.HaloState.CONNECTED, R.drawable.status_dot_green)
                dastyabStatus.state == DastyabVpnService.State.CONNECTING ->
                    setBrowserHalo(StatusHaloView.HaloState.CONNECTING, R.drawable.status_dot_orange)
                else ->
                    setBrowserHalo(StatusHaloView.HaloState.IDLE, R.drawable.status_dot_gray)
            }
            if (precomputed != null && this::tvRouteStatus.isInitialized) {
                tvRouteStatus.text = getString(R.string.browser_checking_country, precomputed.routeLabel)
            }
        } catch (_: Throwable) {
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onBackPressed() {
        val wv = currentWebView
        if (wv != null && wv.canGoBack()) {
            wv.goBack()
        } else {
            @Suppress("DEPRECATION")
            super.onBackPressed()
        }
    }

    override fun onDestroy() {
        if (receiverRegistered) {
            try { unregisterReceiver(stateReceiver) } catch (_: Exception) {}
            receiverRegistered = false
        }
        val destroyed = HashSet<WebView>()
        for (wv in profileWebViews.values.toList()) {
            destroyed.add(wv)
            destroyWebViewInstance(wv)
        }
        profileWebViews.clear()
        currentWebView?.let { wv ->
            if (wv !in destroyed) destroyWebViewInstance(wv)
        }
        currentWebView = null
        super.onDestroy()
    }
}
