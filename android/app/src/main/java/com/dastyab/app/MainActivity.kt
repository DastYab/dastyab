package com.dastyab.app

import android.app.Activity
import android.app.AlertDialog
import android.content.BroadcastReceiver
import android.content.Context
import android.content.Intent
import android.content.IntentFilter
import android.graphics.Typeface
import android.net.Uri
import android.net.VpnService
import android.os.Build
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.text.Spannable
import android.text.SpannableStringBuilder
import android.text.style.ClickableSpan
import android.text.style.ForegroundColorSpan
import android.text.style.StyleSpan
import android.view.View
import android.view.inputmethod.EditorInfo
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.ScrollView
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import org.json.JSONObject
import java.io.File
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

/**
 * MainActivity — DastYab Android control plane.
 *
 * Combines:
 *  • Built-in Smart / Global / Split VPN Tunnel (with auto-VPN for AI Studio & Google Flow)
 *  • 14 one-tap Quick Actions covering Google access, Worker deploy, Autopilot,
 *    Clean IP scanning, Profiles, Tokens, Configs, Security Audit, Doctor, Backup, and Zones
 *  • Full interactive CLI console with history, quick-command chips, and clickable URLs
 */
class MainActivity : DastyabActivity() {
    private lateinit var status: TextView
    private lateinit var output: TextView
    private lateinit var outputEmptyState: LinearLayout
    private lateinit var argsInput: EditText
    private lateinit var btnRun: Button
    private lateinit var btnCancel: Button
    private lateinit var progress: ProgressBar
    private lateinit var statusDot: View
    private lateinit var historySpinner: Spinner
    private lateinit var binary: File

    // Simple / Advanced / Terminal Mode views
    private lateinit var btnTabSimple: Button
    private lateinit var btnTabAdvanced: Button
    private lateinit var btnTabTerminal: Button
    private lateinit var simpleModeContainer: LinearLayout
    private lateinit var advancedModeContainer: LinearLayout
    private lateinit var terminalModeContainer: LinearLayout
    private lateinit var simpleStatusDot: View
    private lateinit var tvSimpleHeroTitle: TextView
    private lateinit var tvSimpleReachability: TextView
    private lateinit var tvSimpleStepLine: TextView
    private lateinit var simpleProgress: ProgressBar
    private lateinit var btnSimpleMagicAutopilot: Button
    private lateinit var btnSimpleQuickToggle: Button
    private lateinit var btnIntentBalanced: Button
    private lateinit var btnIntentAiStudio: Button
    private lateinit var btnIntentFlow: Button
    private lateinit var btnIntentBlackout: Button
    private lateinit var simpleConnectedActions: LinearLayout
    private lateinit var btnSimpleLaunchAiStudio: Button
    private lateinit var btnSimpleLaunchFlow: Button
    private lateinit var btnToggleBrainDrawer: Button
    private lateinit var simpleBrainDrawer: LinearLayout
    private lateinit var tvSimpleBrainDetails: TextView
    private lateinit var btnResetBrain: Button

    // Terminal Mode views (CPython 3.11 Linux-compatible shell)
    private lateinit var tvTerminalRuntimeBadge: TextView
    private lateinit var tvTerminalPromptHeader: TextView
    private lateinit var terminalOutputScroll: ScrollView
    private lateinit var tvTerminalOutput: TextView
    private lateinit var terminalProgress: ProgressBar
    private lateinit var terminalInput: EditText
    private lateinit var btnTerminalRun: Button
    private lateinit var btnTerminalStop: Button
    private val terminalRunning = AtomicBoolean(false)
    private val terminalProcessHolder = AtomicReference<Process?>(null)
    @Volatile
    private var terminalBannerShown = false

    // VPN Tunnel card views (Advanced Mode)
    private lateinit var vpnDot: View
    private lateinit var tvVpnState: TextView
    private lateinit var tvVpnDetails: TextView
    private lateinit var tvReachabilityBadge: TextView
    private lateinit var btnNewbieAutopilot: Button
    private lateinit var btnVpnToggle: Button
    private lateinit var btnModeSmart: Button
    private lateinit var btnModeGlobal: Button
    private lateinit var btnModeSplit: Button
    private lateinit var btnModeDns: Button

    // Quick action cards (entire card is clickable)
    private lateinit var btnSimpleAistudio: View
    private lateinit var btnSimpleFlow: View
    private lateinit var btnSimpleDeploy: View
    private lateinit var btnSimpleAutopilot: View
    private lateinit var btnSimpleVerify: View
    private lateinit var btnSimpleAccounts: View
    private lateinit var btnSimpleProfiles: View
    private lateinit var btnSimpleTokens: View
    private lateinit var btnSimpleScan: View
    private lateinit var btnSimpleConfigs: View
    private lateinit var btnSimpleSecurity: View
    private lateinit var btnSimpleDoctor: View
    private lateinit var btnSimpleBackup: View
    private lateinit var btnSimpleZones: View

    // Advanced section toggle
    private lateinit var btnShowAdvanced: Button
    private lateinit var btnHideAdvanced: Button
    private lateinit var advancedSection: LinearLayout

    private val handler = Handler(Looper.getMainLooper())
    private val uiLock = Any()
    private var destroyed = false // Protected by uiLock, including callback enqueue/removal.
    private val operation = AtomicReference<Operation?>(null)
    private var pendingGoogleLaunchUrl: String? = null
    private var pendingGoogleLaunchName: String? = null
    private var vpnReceiverRegistered = false
    private val postConnectGeoInFlight = AtomicBoolean(false)
    private val flowWarriorInFlight = AtomicBoolean(false)
    private var pendingUpdateApk: File? = null

    private val vpnStateReceiver = object : BroadcastReceiver() {
        override fun onReceive(context: Context?, intent: Intent?) {
            if (UiSafety.isActivityAlive(this@MainActivity)) {
                if (intent?.action == BypassStateStore.ACTION_BYPASS_SUCCESSFUL) {
                    val service = intent.getStringExtra(BypassStateStore.EXTRA_SERVICE) ?: "AI Studio"
                    val route = intent.getStringExtra(BypassStateStore.EXTRA_ROUTE) ?: "Brutal Chain"
                    val msg = "Protected & Bypassed ✓ ($service via $route)"
                    runCatching {
                        tvSimpleReachability.text = msg
                        tvReachabilityBadge.text = msg
                        setStatusDot(DotState.GREEN)
                        postStatus(msg)
                    }
                }
                refreshVpnCard()
            }
        }
    }

    private class Operation {
        val cancelled = AtomicBoolean(false)
        val process = AtomicReference<Process?>(null)
    }

    companion object {
        const val EXTRA_AUTO_CONNECT_VPN = "extra_auto_connect_vpn"
        private const val PROCESS_TIMEOUT_MS = 300_000L
        private const val MAX_OUTPUT_CHARS = 50_000
        private const val MAX_ARGS_LENGTH = 4096
        private const val REQ_VPN_PREPARE = 4001
    }

    override fun initializeBeforeTheme() {
        DastyabLogger.init(filesDir)
        CrashHandler.install(applicationContext, filesDir)
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_main)

        status = findViewById(R.id.status)
        output = findViewById(R.id.output)
        outputEmptyState = findViewById(R.id.outputEmptyState)
        argsInput = findViewById(R.id.argsInput)
        btnRun = findViewById(R.id.btnRun)
        btnCancel = findViewById(R.id.btnCancel)
        progress = findViewById(R.id.progress)
        statusDot = findViewById(R.id.statusDot)
        historySpinner = findViewById(R.id.historySpinner)
        binary = File(applicationInfo.nativeLibraryDir, "libdastyab.so")

        // Simple / Advanced / Terminal Mode bindings
        btnTabSimple = findViewById(R.id.btnTabSimple)
        btnTabAdvanced = findViewById(R.id.btnTabAdvanced)
        btnTabTerminal = findViewById(R.id.btnTabTerminal)
        simpleModeContainer = findViewById(R.id.simpleModeContainer)
        advancedModeContainer = findViewById(R.id.advancedModeContainer)
        terminalModeContainer = findViewById(R.id.terminalModeContainer)
        simpleStatusDot = findViewById(R.id.simpleStatusDot)
        tvSimpleHeroTitle = findViewById(R.id.tvSimpleHeroTitle)
        tvSimpleReachability = findViewById(R.id.tvSimpleReachability)
        tvSimpleStepLine = findViewById(R.id.tvSimpleStepLine)
        simpleProgress = findViewById(R.id.simpleProgress)
        btnSimpleMagicAutopilot = findViewById(R.id.btnSimpleMagicAutopilot)
        btnSimpleQuickToggle = findViewById(R.id.btnSimpleQuickToggle)
        btnIntentBalanced = findViewById(R.id.btnIntentBalanced)
        btnIntentAiStudio = findViewById(R.id.btnIntentAiStudio)
        btnIntentFlow = findViewById(R.id.btnIntentFlow)
        btnIntentBlackout = findViewById(R.id.btnIntentBlackout)
        simpleConnectedActions = findViewById(R.id.simpleConnectedActions)
        btnSimpleLaunchAiStudio = findViewById(R.id.btnSimpleLaunchAiStudio)
        btnSimpleLaunchFlow = findViewById(R.id.btnSimpleLaunchFlow)
        btnToggleBrainDrawer = findViewById(R.id.btnToggleBrainDrawer)
        simpleBrainDrawer = findViewById(R.id.simpleBrainDrawer)
        tvSimpleBrainDetails = findViewById(R.id.tvSimpleBrainDetails)
        btnResetBrain = findViewById(R.id.btnResetBrain)

        // Terminal Mode bindings
        tvTerminalRuntimeBadge = findViewById(R.id.tvTerminalRuntimeBadge)
        tvTerminalPromptHeader = findViewById(R.id.tvTerminalPromptHeader)
        terminalOutputScroll = findViewById(R.id.terminalOutputScroll)
        tvTerminalOutput = findViewById(R.id.tvTerminalOutput)
        terminalProgress = findViewById(R.id.terminalProgress)
        terminalInput = findViewById(R.id.terminalInput)
        btnTerminalRun = findViewById(R.id.btnTerminalRun)
        btnTerminalStop = findViewById(R.id.btnTerminalStop)

        // VPN Tunnel card bindings
        vpnDot = findViewById(R.id.vpnDot)
        tvVpnState = findViewById(R.id.tvVpnState)
        tvVpnDetails = findViewById(R.id.tvVpnDetails)
        tvReachabilityBadge = findViewById(R.id.tvReachabilityBadge)
        btnNewbieAutopilot = findViewById(R.id.btnNewbieAutopilot)
        btnVpnToggle = findViewById(R.id.btnVpnToggle)
        btnModeSmart = findViewById(R.id.btnModeSmart)
        btnModeGlobal = findViewById(R.id.btnModeGlobal)
        btnModeSplit = findViewById(R.id.btnModeSplit)
        btnModeDns = findViewById(R.id.btnModeDns)

        // Quick action card bindings
        btnSimpleAistudio = findViewById(R.id.btnSimpleAistudio)
        btnSimpleFlow = findViewById(R.id.btnSimpleFlow)
        btnSimpleDeploy = findViewById(R.id.btnSimpleDeploy)
        btnSimpleAutopilot = findViewById(R.id.btnSimpleAutopilot)
        btnSimpleVerify = findViewById(R.id.btnSimpleVerify)
        btnSimpleAccounts = findViewById(R.id.btnSimpleAccounts)
        btnSimpleProfiles = findViewById(R.id.btnSimpleProfiles)
        btnSimpleTokens = findViewById(R.id.btnSimpleTokens)
        btnSimpleScan = findViewById(R.id.btnSimpleScan)
        btnSimpleConfigs = findViewById(R.id.btnSimpleConfigs)
        btnSimpleSecurity = findViewById(R.id.btnSimpleSecurity)
        btnSimpleDoctor = findViewById(R.id.btnSimpleDoctor)
        btnSimpleBackup = findViewById(R.id.btnSimpleBackup)
        btnSimpleZones = findViewById(R.id.btnSimpleZones)

        // Advanced section toggle
        btnShowAdvanced = findViewById(R.id.btnShowAdvanced)
        btnHideAdvanced = findViewById(R.id.btnHideAdvanced)
        advancedSection = findViewById(R.id.advancedSection)

        CommandHistory.init(filesDir)
        applyPersistedSettings()

        val version = try {
            packageManager.getPackageInfo(packageName, 0).versionName ?: "unknown"
        } catch (_: Exception) { "unknown" }
        findViewById<TextView>(R.id.tvVersion).text = getString(R.string.version_format, version)
        savedInstanceState?.getString("pendingOutput")?.let { applyFormattedOutput(it) }

        // ── Normal Chain vs Emergency Mode Toggle ──
        val btnModeToggle = findViewById<Button>(R.id.btnModeToggle)
        fun refreshModeToggleLabel() {
            val mode = TunnelConfig.load(this).mode
            btnModeToggle.text = if (mode == TunnelConfig.Mode.DNS_BLACKOUT) {
                getString(R.string.mode_emergency_badge)
            } else {
                getString(R.string.mode_normal_badge)
            }
        }
        refreshModeToggleLabel()
        btnModeToggle.setOnClickListener {
            val cur = TunnelConfig.load(this).mode
            val newMode = if (cur == TunnelConfig.Mode.DNS_BLACKOUT) {
                TunnelConfig.Mode.SMART
            } else {
                TunnelConfig.Mode.DNS_BLACKOUT
            }
            TunnelConfig.saveMode(this, newMode)
            refreshModeToggleLabel()
            refreshVpnCard()
            if (DastyabVpnService.isConnected()) {
                DastyabVpnService.start(this)
                Toast.makeText(
                    this,
                    getString(R.string.main_switched_mode_reconnected, newMode.localizedLabel(this)),
                    Toast.LENGTH_LONG
                ).show()
            } else {
                Toast.makeText(
                    this,
                    getString(R.string.main_switched_mode, newMode.localizedLabel(this)),
                    Toast.LENGTH_SHORT
                ).show()
            }
        }

        // ── Theme Picker Toggle (4 Light + 2 Dark + Follow System) ──
        findViewById<Button>(R.id.btnThemeToggle).apply {
            text = ThemeManager.badgeLabel(this@MainActivity)
            setOnClickListener {
                ThemeManager.showThemePickerDialog(this@MainActivity) {
                    recreate()
                }
            }
        }

        // ── 6-Language Multilingual Toggle (EN / FA / AR / TR / RU / ZH) ──
        findViewById<Button>(R.id.btnLangToggle).apply {
            text = LocaleHelper.badgeLabel(LocaleHelper.getLanguage(this@MainActivity))
            setOnClickListener {
                LocaleHelper.showLanguagePickerDialog(this@MainActivity) {
                    DastyabWidgetProvider.updateAllWidgets(this@MainActivity)
                    recreate()
                }
            }
        }

        // ── Simple / Advanced / Terminal Mode Switcher ──
        btnTabSimple.setOnClickListener { applyUiMode(UiModePrefs.Mode.SIMPLE) }
        btnTabAdvanced.setOnClickListener { applyUiMode(UiModePrefs.Mode.ADVANCED) }
        btnTabTerminal.setOnClickListener { applyUiMode(UiModePrefs.Mode.TERMINAL) }
        setupTerminalModeUi()
        applyUiMode(UiModePrefs.getMode(this), persist = false)

        // ── Simple Mode 1-Click & Intent Controls ──
        AutopilotBrain.ensureLoaded(this)
        refreshIntentChips(AutopilotBrain.getSavedIntent(this))
        btnIntentBalanced.setOnClickListener { selectAutopilotIntent(AutopilotBrain.AutopilotIntent.BALANCED_WEB) }
        btnIntentAiStudio.setOnClickListener { selectAutopilotIntent(AutopilotBrain.AutopilotIntent.AI_STUDIO) }
        btnIntentFlow.setOnClickListener { selectAutopilotIntent(AutopilotBrain.AutopilotIntent.GOOGLE_FLOW) }
        btnIntentBlackout.setOnClickListener { selectAutopilotIntent(AutopilotBrain.AutopilotIntent.BLACKOUT_SURVIVAL) }

        btnSimpleMagicAutopilot.setOnClickListener { runNewbieAutopilot() }
        btnSimpleLaunchAiStudio.setOnClickListener {
            openBrowserUrl(getString(R.string.service_name_aistudio), CommandCompat.AISTUDIO_URL)
        }
        btnSimpleLaunchFlow.setOnClickListener {
            if (operation.get() == null) runFlowWarriorAndOpen()
        }
        btnToggleBrainDrawer.setOnClickListener {
            val opening = simpleBrainDrawer.visibility != View.VISIBLE
            simpleBrainDrawer.visibility = if (opening) View.VISIBLE else View.GONE
            btnToggleBrainDrawer.text = getString(
                if (opening) R.string.simple_brain_toggle_hide else R.string.simple_brain_toggle_show
            )
            if (opening) refreshBrainDrawer()
        }
        btnResetBrain.setOnClickListener {
            AutopilotBrain.clearAllLearned(this)
            FlowWarriorEngine.clearWarriorMemory(this)
            refreshIntentChips(AutopilotBrain.AutopilotIntent.BALANCED_WEB)
            refreshBrainDrawer()
            Toast.makeText(this, getString(R.string.simple_brain_reset_done), Toast.LENGTH_SHORT).show()
        }

        btnSimpleQuickToggle.setOnClickListener { toggleVpnTunnel() }
        findViewById<Button>(R.id.btnSimpleSpeedIp).setOnClickListener { runQuickSpeedAndIpCheck() }
        findViewById<View>(R.id.btnSimpleLanternAutopilot).setOnClickListener {
            runExternalVpnAutopilotFlow()
        }
        findViewById<View>(R.id.btnSimpleOneClickAiStudio).setOnClickListener {
            if (operation.get() == null) launchGoogleServiceViaVpn(getString(R.string.service_name_aistudio), CommandCompat.AISTUDIO_URL)
        }
        findViewById<View>(R.id.btnSimpleOneClickFlow).setOnClickListener {
            if (operation.get() == null) runFlowWarriorAndOpen()
        }
        findViewById<View>(R.id.btnSimpleOneClickRefresh).setOnClickListener {
            openRescueHub(BlackoutRescueActivity.ACTION_HARVEST)
        }
        findViewById<View>(R.id.btnSimpleOneClickBlackout).setOnClickListener {
            openRescueHub(BlackoutRescueActivity.ACTION_DNS_VPN)
        }
        findViewById<View>(R.id.btnSimpleCfStudio).setOnClickListener {
            openActivity(CloudflareWorkerActivity::class.java)
        }
        findViewById<Button>(R.id.btnSimpleProxyPort).setOnClickListener {
            GoogleAccessSheet.show(this) { refreshVpnCard() }
        }
        findViewById<Button>(R.id.btnSimpleLayerPick).setOnClickListener {
            showQuickLayerSwitcherDialog()
        }
        findViewById<Button>(R.id.btnSimpleGoAdvanced).setOnClickListener {
            applyUiMode(UiModePrefs.Mode.ADVANCED)
        }

        // ── VPN Tunnel controls (Advanced Mode) ──
        btnNewbieAutopilot.setOnClickListener { runNewbieAutopilot() }
        btnVpnToggle.setOnClickListener { toggleVpnTunnel() }
        btnModeSmart.setOnClickListener { switchTunnelMode(TunnelConfig.Mode.SMART) }
        btnModeGlobal.setOnClickListener { switchTunnelMode(TunnelConfig.Mode.GLOBAL) }
        btnModeSplit.setOnClickListener { switchTunnelMode(TunnelConfig.Mode.SPLIT_INCLUDE) }
        btnModeDns.setOnClickListener { switchTunnelMode(TunnelConfig.Mode.DNS_BLACKOUT) }
        findViewById<Button>(R.id.btnTunnelSettings).setOnClickListener {
            openActivity(TunnelSettingsActivity::class.java)
        }
        findViewById<Button>(R.id.btnImportVless).setOnClickListener {
            showImportVlessDialog()
        }
        findViewById<Button>(R.id.btnSwitchLayer).setOnClickListener {
            showQuickLayerSwitcherDialog()
        }
        findViewById<Button>(R.id.btnShareQr).setOnClickListener {
            val layer = VpnLayerStore.getActiveLayer(this)
            val cfg = layer.configUri.ifBlank { TunnelConfig.load(this).vlessUri }
                .ifBlank { TunnelConfig.loadHarvestedConfigs(this).firstOrNull().orEmpty() }
            QrShareDialog.show(this, "QR · ${layer.name}", cfg)
        }
        findViewById<Button>(R.id.btnDnsRules).setOnClickListener {
            DomainDnsDialog.show(this) { refreshVpnCard() }
        }
        findViewById<Button>(R.id.btnGoogleAccessMode).setOnClickListener {
            GoogleAccessSheet.show(this) { refreshVpnCard() }
        }

        // ── Blackout Rescue & Harvesting Quick Actions ──
        findViewById<View>(R.id.btnSimpleHarvest).setOnClickListener {
            openRescueHub(BlackoutRescueActivity.ACTION_HARVEST)
        }
        findViewById<View>(R.id.btnSimpleDnsBlackout).setOnClickListener {
            openRescueHub(BlackoutRescueActivity.ACTION_DNS_VPN)
        }
        findViewById<View>(R.id.btnSimpleIpScout).setOnClickListener {
            openRescueHub(BlackoutRescueActivity.ACTION_SCOUT)
        }
        findViewById<View>(R.id.btnSimpleTroubleshoot).setOnClickListener {
            openRescueHub(BlackoutRescueActivity.ACTION_TROUBLESHOOT)
        }
        findViewById<View>(R.id.btnSimpleVpnLayers).setOnClickListener {
            openActivity(VpnLayersActivity::class.java)
        }
        findViewById<View>(R.id.btnSimpleEditSources).setOnClickListener {
            openActivity(VpnLayersActivity::class.java)
        }
        findViewById<View>(R.id.btnSimpleToolbox).setOnClickListener {
            openActivity(NetworkToolboxActivity::class.java)
        }

        // ── Google & Tunnel Quick Actions ──
        btnSimpleAistudio.setOnClickListener {
            if (operation.get() == null) launchGoogleServiceViaVpn(getString(R.string.service_name_aistudio), CommandCompat.AISTUDIO_URL)
        }
        btnSimpleAistudio.setOnLongClickListener {
            showGoogleRescueDialog(getString(R.string.service_name_aistudio), CommandCompat.AISTUDIO_URL)
            true
        }
        btnSimpleFlow.setOnClickListener {
            if (operation.get() == null) runFlowWarriorAndOpen()
        }
        btnSimpleFlow.setOnLongClickListener {
            showGoogleRescueDialog(getString(R.string.service_name_flow), CommandCompat.FLOW_URL)
            true
        }
        btnSimpleDeploy.setOnClickListener {
            openActivity(CloudflareWorkerActivity::class.java)
        }
        btnSimpleAutopilot.setOnClickListener {
            if (operation.get() == null) runSimple("autopilot status", listOf("autopilot", "status"))
        }

        // ── Cloudflare & Stack Quick Actions ──
        btnSimpleVerify.setOnClickListener {
            if (operation.get() == null) runSimple("verify", listOf("verify"))
        }
        btnSimpleAccounts.setOnClickListener {
            if (operation.get() == null) runSimple("accounts", listOf("accounts"))
        }
        btnSimpleProfiles.setOnClickListener {
            if (operation.get() == null) runSimple("profiles", listOf("profiles"))
        }
        btnSimpleTokens.setOnClickListener {
            if (operation.get() == null) runSimple("token-list", listOf("token-list"))
        }
        btnSimpleScan.setOnClickListener {
            if (operation.get() == null) runSimple("scan", listOf("scan"))
        }
        btnSimpleConfigs.setOnClickListener {
            if (operation.get() == null) runSimple("configs", listOf("configs"))
        }
        btnSimpleSecurity.setOnClickListener {
            if (operation.get() == null) runSimple("security", listOf("security"))
        }
        btnSimpleDoctor.setOnClickListener {
            if (operation.get() == null) runSimple("doctor", listOf("doctor"))
        }
        btnSimpleBackup.setOnClickListener {
            if (operation.get() == null) runSimple("backup", listOf("backup"))
        }
        btnSimpleZones.setOnClickListener {
            if (operation.get() == null) runSimple("zones", listOf("zones"))
        }

        // ── Advanced toggle ──
        btnShowAdvanced.setOnClickListener { showAdvanced() }
        btnHideAdvanced.setOnClickListener { hideAdvanced() }

        // ── Run / cancel ──
        btnRun.setOnClickListener { runTyped() }
        btnCancel.setOnClickListener { cancelCurrentOperation() }

        findViewById<Button>(R.id.btnClear).setOnClickListener {
            output.text = ""
            outputEmptyState.visibility = View.VISIBLE
            output.visibility = View.GONE
        }

        findViewById<Button>(R.id.btnViewLogs).setOnClickListener {
            openActivity(LogViewerActivity::class.java)
        }
        findViewById<Button>(R.id.btnAbout).setOnClickListener { openActivity(AboutActivity::class.java) }
        findViewById<Button>(R.id.btnSettings).setOnClickListener { openActivity(SettingsActivity::class.java) }
        findViewById<Button>(R.id.btnUpdate).apply {
            text = getString(R.string.btn_releases)
            setOnClickListener {
                try {
                    startActivity(Intent(Intent.ACTION_VIEW, Uri.parse("https://github.com/DastYab/dastyab/releases")))
                } catch (_: android.content.ActivityNotFoundException) {
                    postStatus(getString(R.string.main_no_browser_releases))
                }
            }
        }
        findViewById<Button>(R.id.btnCopy).setOnClickListener {
            if (UiSafety.copyTextSafely(this, "Dastyab output", output.text.toString())) {
                Toast.makeText(this, getString(R.string.copied_to_clipboard), Toast.LENGTH_SHORT).show()
            }
        }
        findViewById<Button>(R.id.btnShare).setOnClickListener {
            val text = output.text.toString()
            if (text.isNotEmpty()) {
                val share = Intent.createChooser(Intent(Intent.ACTION_SEND).apply {
                    type = "text/plain"
                    putExtra(Intent.EXTRA_TEXT, text)
                }, getString(R.string.share_title))
                if (!UiSafety.safeStartActivity(this, share)) {
                    Toast.makeText(this, getString(R.string.copied_to_clipboard), Toast.LENGTH_SHORT).show()
                    UiSafety.copyTextSafely(this, "Dastyab output", text)
                }
            }
        }
        findViewById<Button>(R.id.btnHistory).setOnClickListener {
            val entries = CommandHistory.getAll()
            if (entries.isEmpty()) {
                Toast.makeText(this, getString(R.string.history_empty), Toast.LENGTH_SHORT).show()
            } else {
                UiSafety.safeShowDialog(
                    this,
                    AlertDialog.Builder(this).setTitle(getString(R.string.history_dialog_title))
                        .setItems(entries.map { it.command }.toTypedArray()) { _, index ->
                            argsInput.setText(entries[index].command)
                        }.setPositiveButton(android.R.string.ok, null)
                )
            }
        }

        buildQuickButtons(R.id.quickButtons, listOf(
            "--help", "--version", "verify", "accounts", "scan",
            "deploy --preset standard", "autopilot status", "doctor", "security"
        ))
        buildQuickButtons(R.id.quickButtonsProfiles, listOf(
            "profiles", "token-list", "configs", "zones", "routes list",
            "manifest-verify", "inventory", "backup", "update-check"
        ))
        setupHistorySpinner()
        registerVpnReceiver()
        refreshVpnCard()
        setBusy(false)
        evaluateBinaryState()

        CrashHandler.consumePendingCrashNotice()?.let { notice ->
            showSafeModeRecoveryDialog(notice)
        }

        val initialSettings = TunnelConfig.load(this)
        if (initialSettings.autoStartLocalBridge && !LocalProxyService.isRunning()) {
            LocalProxyService.startSafely(this)
        }

        if (intent?.getBooleanExtra(EXTRA_AUTO_CONNECT_VPN, false) == true && !DastyabVpnService.isConnected()) {
            requestStartVpn(null, null)
        }

        AppAutoUpdater.cleanupStaleUpdates(this)
        if (AppAutoUpdater.isCheckDue(this)) {
            startBackgroundAppUpdateCheck()
        }
    }

    private fun startBackgroundAppUpdateCheck() {
        thread(isDaemon = true, name = "dastyab-app-autoupdate") {
            val outcome = AppAutoUpdater.checkAndDownloadIfNeeded(applicationContext, force = false)
            if (outcome is AppAutoUpdater.CheckOutcome.ReadyToInstall) {
                runOnUiThread {
                    if (UiSafety.isActivityAlive(this)) {
                        promptApkUpdateReady(outcome)
                    }
                }
            }
        }
    }

    private fun promptApkUpdateReady(ready: AppAutoUpdater.CheckOutcome.ReadyToInstall) {
        pendingUpdateApk = ready.apkFile
        postStatus(getString(R.string.app_update_ready_title, ready.remoteTag))
        val builder = AlertDialog.Builder(this)
            .setTitle(getString(R.string.app_update_ready_title, ready.remoteTag))
            .setMessage(
                getString(
                    R.string.app_update_ready_msg,
                    ready.currentVersion,
                    ready.remoteTag,
                    ready.assetName
                )
            )
            .setPositiveButton(getString(R.string.app_update_install_now)) { _, _ ->
                if (!AppAutoUpdater.launchInstallerOrRequestPermission(this, ready.apkFile)) {
                    Toast.makeText(
                        this,
                        getString(R.string.app_update_permission_msg),
                        Toast.LENGTH_LONG
                    ).show()
                } else {
                    pendingUpdateApk = null
                }
            }
            .setNeutralButton(getString(R.string.app_update_skip)) { _, _ ->
                pendingUpdateApk = null
                AppAutoUpdater.markTagSkipped(this, ready.remoteTag)
            }
            .setNegativeButton(getString(R.string.app_update_later)) { _, _ ->
                pendingUpdateApk = null
            }
        UiSafety.safeShowDialog(this, builder)
    }

    private fun showSafeModeRecoveryDialog(notice: String) {
        val builder = AlertDialog.Builder(this)
            .setTitle(getString(R.string.main_safe_mode_title))
            .setMessage(getString(R.string.main_safe_mode_message, notice))
            .setPositiveButton(getString(R.string.main_safe_mode_view_logs)) { _, _ ->
                openActivity(LogViewerActivity::class.java)
            }
            .setNegativeButton(android.R.string.ok, null)
        UiSafety.safeShowDialog(this, builder)
    }

    override fun onResume() {
        super.onResume()
        refreshVpnCard()
        val pending = pendingUpdateApk
        if (pending != null && pending.isFile) {
            if (Build.VERSION.SDK_INT < Build.VERSION_CODES.O ||
                packageManager.canRequestPackageInstalls()
            ) {
                pendingUpdateApk = null
                AppAutoUpdater.launchInstallerOrRequestPermission(this, pending)
            }
        }
    }

    private fun registerVpnReceiver() {
        if (vpnReceiverRegistered) return
        val filter = IntentFilter().apply {
            addAction(DastyabVpnService.ACTION_STATE_CHANGED)
            addAction(LocalProxyService.ACTION_STATE_CHANGED)
            addAction(BypassStateStore.ACTION_BYPASS_SUCCESSFUL)
        }
        if (Build.VERSION.SDK_INT >= 33) {
            registerReceiver(vpnStateReceiver, filter, Context.RECEIVER_NOT_EXPORTED)
        } else {
            @Suppress("DEPRECATION")
            registerReceiver(vpnStateReceiver, filter)
        }
        vpnReceiverRegistered = true
    }

    private fun toggleVpnTunnel() {
        if (DastyabVpnService.isConnected()) {
            DastyabVpnService.stop(this)
            postOutput(getString(R.string.main_vpn_disconnected_log) + "\n")
            refreshVpnCard()
            return
        }
        requestStartVpn(null, null)
    }

    private fun switchTunnelMode(mode: TunnelConfig.Mode) {
        TunnelConfig.saveMode(this, mode)
        refreshVpnCard()
        if (DastyabVpnService.isConnected()) {
            DastyabVpnService.start(this)
            postOutput(getString(R.string.main_switched_mode_reconnected, mode.localizedLabel(this)) + "\n")
        } else {
            Toast.makeText(
                this,
                getString(R.string.main_tunnel_mode_toast, mode.localizedLabel(this)),
                Toast.LENGTH_SHORT
            ).show()
        }
    }

    private fun requestStartVpn(launchName: String?, launchUrl: String?) {
        pendingGoogleLaunchName = launchName
        pendingGoogleLaunchUrl = launchUrl
        val prepIntent = VpnService.prepare(this)
        if (prepIntent != null) {
            try {
                @Suppress("DEPRECATION")
                startActivityForResult(prepIntent, REQ_VPN_PREPARE)
            } catch (_: Exception) {
                postOutput(getString(R.string.rescue_vpn_consent_unavailable) + "\n")
                openPendingGoogleUrlIfAny()
            }
        } else {
            DastyabVpnService.start(this)
            refreshVpnCard()
            if (launchUrl != null) {
                openPendingGoogleUrlIfAny()
            } else {
                verifyAndEnsureNoGeoBlockAfterConnect()
            }
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN_PREPARE) {
            if (resultCode == RESULT_OK) {
                AutopilotBrain.markConsentRemembered(this, true)
                DastyabVpnService.start(this)
                postOutput(getString(R.string.main_vpn_started_log) + "\n")
                refreshVpnCard()
                if (pendingGoogleLaunchUrl != null) {
                    openPendingGoogleUrlIfAny()
                } else {
                    verifyAndEnsureNoGeoBlockAfterConnect()
                }
            } else {
                postOutput(getString(R.string.main_vpn_declined_log) + "\n")
                val failedName = pendingGoogleLaunchName
                val failedUrl = pendingGoogleLaunchUrl
                pendingGoogleLaunchName = null
                pendingGoogleLaunchUrl = null
                if (failedName != null && failedUrl != null) {
                    showGoogleRescueDialog(failedName, failedUrl)
                }
            }
        }
    }

    /**
     * Runs immediately whenever Connect activates DastYab VPN without opening a specific URL:
     * verifies TRUE non-geoblocked access for both AI Studio & Google Flow (never trusting HTTP 200),
     * and autonomously harvests + multi-layer chains non-georestricted IPs if either site is geo-blocked.
     */
    private fun verifyAndEnsureNoGeoBlockAfterConnect() {
        if (!postConnectGeoInFlight.compareAndSet(false, true)) return
        val checkingLabel = getString(R.string.main_connect_verifying_geo)
        simpleProgress.visibility = View.VISIBLE
        tvSimpleReachability.text = checkingLabel
        tvReachabilityBadge.text = checkingLabel
        postStatus(checkingLabel)
        setStatusDot(DotState.ORANGE)
        postOutput("[connect] $checkingLabel\n")

        thread(isDaemon = true, name = "dastyab-post-connect-geo") {
            try {
                try { Thread.sleep(700) } catch (_: InterruptedException) {}
                val settings = TunnelConfig.load(this)
                val aiRoute = GeoBypassEngine.resolveCurrentRoute(this, settings, GeoBypassEngine.TargetService.AI_STUDIO)
                var aiProbe = GeoBypassEngine.runAccessProbe(aiRoute, timeoutMs = 4000)

                val excludedIps = LinkedHashSet<String>()
                if (!aiProbe.readyForAiStudio) aiProbe.egress?.ip?.takeIf { it.isNotBlank() }?.let { excludedIps.add(it) }

                if (!aiProbe.readyForAiStudio) {
                    val ccTag = aiProbe.egress?.countryCode ?: "??"
                    val chainBanner = getString(R.string.main_connect_auto_chaining, "AI Studio", ccTag)
                    postUi {
                        if (!UiSafety.isActivityAlive(this)) return@postUi
                        tvSimpleReachability.text = chainBanner
                        tvReachabilityBadge.text = chainBanner
                        postStatus(chainBanner)
                    }
                    postOutput("[connect] $chainBanner\n")

                    val aiRes = GeoBypassEngine.discoverAndChainBestRoute(
                        context = this,
                        targetService = GeoBypassEngine.TargetService.AI_STUDIO,
                        allowHarvest = true,
                        maxCandidates = 44,
                        excludedEgressIps = excludedIps,
                        excludeCurrentRoute = true,
                        excludedChainSpecs = setOfNotNull(aiRoute.upstreamChainSpec.takeIf { it.isNotBlank() }),
                        maxRounds = 3
                    ) { step -> postOutput("  [connect-ai] $step\n") }
                    aiProbe = aiRes.report
                    if (aiRes.success && DastyabVpnService.isConnected()) {
                        DastyabVpnService.start(this)
                    }
                }

                val aiOk = aiProbe.readyForAiStudio
                val finalCc = aiProbe.egress?.countryCode ?: "??"
                val finalIp = aiProbe.egress?.ip ?: ""

                postUi {
                    if (!UiSafety.isActivityAlive(this)) return@postUi
                    simpleProgress.visibility = View.GONE
                    refreshVpnCard()
                    if (aiOk) {
                        val msg = getString(R.string.main_connect_all_clear, finalCc)
                        tvSimpleReachability.text = msg
                        tvReachabilityBadge.text = msg
                        postStatus(msg)
                        setStatusDot(DotState.GREEN)
                        postOutput("[connect] $msg ($finalIp)\n")
                    } else {
                        val aiTag = "AI Studio Geo-Blocked ✗"
                        val badge = "$finalCc · $aiTag"
                        tvSimpleReachability.text = badge
                        tvReachabilityBadge.text = badge
                        postStatus(badge)
                        setStatusDot(DotState.ORANGE)
                        postOutput("[connect] AI Studio check: $badge (IP: $finalIp)\n")
                    }
                }
            } finally {
                postConnectGeoInFlight.set(false)
            }
        }
    }

    private fun openRescueHub(autoAction: String? = null) {
        try {
            val intent = Intent(this, BlackoutRescueActivity::class.java)
            if (autoAction != null) intent.putExtra(BlackoutRescueActivity.EXTRA_AUTO_ACTION, autoAction)
            startActivity(intent)
        } catch (_: android.content.ActivityNotFoundException) {
            postStatus(getString(R.string.main_rescue_unavailable))
        }
    }

    private fun showQuickLayerSwitcherDialog() {
        val layers = VpnLayerStore.loadAll(this)
        val activeId = VpnLayerStore.getActiveLayerId(this)
        val labels = layers.map { l ->
            val mark = if (l.id == activeId) "● " else "   "
            "$mark${l.name} (${l.mode.localizedLabel(this)})"
        } + getString(R.string.main_layer_manage_option)

        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(getString(R.string.main_layer_switcher_title))
                .setItems(labels.toTypedArray()) { _, which ->
                    if (which == layers.size) {
                        openActivity(VpnLayersActivity::class.java)
                    } else {
                        val picked = layers[which]
                        VpnLayerStore.activateLayer(this, picked, restartIfConnected = true)
                        refreshVpnCard()
                        postOutput(getString(R.string.main_layer_switched_log, picked.name, picked.mode.localizedLabel(this)) + "\n")
                        if (!DastyabVpnService.isConnected()) {
                            requestStartVpn(null, null)
                        }
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
        )
    }

    private fun showGoogleRescueDialog(serviceName: String, url: String) {
        val options = arrayOf(
            getString(R.string.main_rescue_opt_open_anyway, serviceName),
            getString(R.string.main_rescue_opt_dns_vpn),
            getString(R.string.main_rescue_opt_harvest),
            getString(R.string.main_rescue_opt_scout),
            getString(R.string.main_rescue_opt_troubleshoot)
        )
        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(getString(R.string.main_rescue_dialog_title, serviceName))
                .setItems(options) { _, which ->
                    when (which) {
                        0 -> openBrowserUrl(serviceName, url)
                        1 -> openRescueHub(BlackoutRescueActivity.ACTION_DNS_VPN)
                        2 -> openRescueHub(BlackoutRescueActivity.ACTION_HARVEST)
                        3 -> openRescueHub(BlackoutRescueActivity.ACTION_SCOUT)
                        4 -> openRescueHub(BlackoutRescueActivity.ACTION_TROUBLESHOOT)
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
        )
    }

    private fun openPendingGoogleUrlIfAny() {
        val url = pendingGoogleLaunchUrl ?: return
        val name = pendingGoogleLaunchName ?: getString(R.string.service_name_google)
        pendingGoogleLaunchUrl = null
        pendingGoogleLaunchName = null
        verifyAndOpenGoogleService(name, url)
    }

    /**
     * 1-Tap Lantern / External VPN Autopilot + Direct Internal Browser Quick Action:
     * Detects active Lantern/system VPN or listening local proxies without overwriting the OS VPN
     * slot, verifies exit country + Flow 151-country gate + HTTPS, and provides 1-tap open into
     * AI Studio & Google Flow inside the built-in browser (or 1-tap Lantern launch if disconnected).
     */
    private fun runExternalVpnAutopilotFlow() {
        if (operation.get() != null) return
        setBusy(true)
        simpleProgress.visibility = View.VISIBLE
        val runningMsg = getString(R.string.lantern_autopilot_running)
        postStatus(runningMsg)
        setStatusDot(DotState.ORANGE)
        tvSimpleReachability.text = runningMsg
        tvReachabilityBadge.text = runningMsg
        applyFormattedOutput("\n=== ${getString(R.string.simple_card_lantern_autopilot)} ===\n")

        thread(isDaemon = true, name = "dastyab-lantern-autopilot") {
            val result = NewbieAutopilot.runExternalVpnAutopilot(
                context = this,
                targetName = getString(R.string.lantern_target_both),
                targetUrl = CommandCompat.AISTUDIO_URL
            ) { step ->
                postOutput("$step\n")
            }
            postUi {
                setBusy(false)
                simpleProgress.visibility = View.GONE
                refreshVpnCard()

                val ccTag = result.exitCountry ?: "??"
                val aiTag = if (result.aiStudioReady) "AI Studio ✓" else "AI Studio ✗"
                val flowTag = if (result.flowReady) "Flow ✓" else "Flow ✗"
                val statusBadge = if (result.aiStudioReady && result.flowReady) {
                    getString(R.string.lantern_badge_ready, ccTag, result.latencyMs, result.routeLabel)
                } else {
                    "$ccTag · $aiTag · $flowTag"
                }
                tvSimpleReachability.text = statusBadge
                tvReachabilityBadge.text = statusBadge
                postStatus(result.headline)
                setStatusDot(
                    when {
                        result.aiStudioReady && result.flowReady -> DotState.GREEN
                        result.needsLanternConnect -> DotState.RED
                        else -> DotState.ORANGE
                    }
                )

                val summaryMsg = getString(
                    R.string.lantern_dialog_dual_body,
                    if (result.aiStudioReady) "READY ✓" else "GEO-BLOCKED ✗",
                    result.aiStudioRouteLabel,
                    if (result.flowReady) "READY ✓" else "GEO-BLOCKED ✗",
                    result.flowRouteLabel,
                    result.exitIp ?: getString(R.string.main_ip_unknown),
                    ccTag,
                    if (result.flowCountrySupported) getString(R.string.main_geo_flow_supported) else getString(R.string.main_geo_flow_blocked),
                    result.recommendation
                )

                val builder = AlertDialog.Builder(this)
                    .setTitle(result.headline)
                    .setMessage(summaryMsg)
                    .setPositiveButton(getString(R.string.autopilot_open_aistudio)) { _, _ ->
                        openBrowserUrl(getString(R.string.service_name_aistudio), CommandCompat.AISTUDIO_URL)
                    }
                    .setNeutralButton(getString(R.string.autopilot_open_flow)) { _, _ ->
                        openBrowserUrl(getString(R.string.service_name_flow), CommandCompat.FLOW_URL)
                    }

                if (result.needsLanternConnect) {
                    val vpnPkg = result.lanternPackage ?: result.installedVpnApps.firstOrNull()?.installedPackage
                    builder.setNegativeButton(getString(R.string.lantern_btn_open_app)) { _, _ ->
                        val launched = vpnPkg?.let { pkg ->
                            packageManager.getLaunchIntentForPackage(pkg)?.let { intent ->
                                UiSafety.safeStartActivity(this, intent)
                            }
                        } ?: false
                        if (!launched) {
                            GoogleAccessSheet.show(this) { refreshVpnCard() }
                        }
                    }
                } else {
                    builder.setNegativeButton(getString(R.string.action_google_route)) { _, _ ->
                        GoogleAccessSheet.show(this) { refreshVpnCard() }
                    }
                }
                UiSafety.safeShowDialog(this, builder)
            }
        }
    }

    private fun launchGoogleServiceViaVpn(serviceName: String, url: String) {
        setBusy(true)
        postStatus(getString(R.string.main_preparing_route, serviceName))
        setStatusDot(DotState.ORANGE)
        thread(isDaemon = true, name = "dastyab-google-launch") {
            val settings = TunnelConfig.load(this)
            val targetService = GeoBypassEngine.TargetService.fromUrl(url)
            var route = GeoBypassEngine.resolveCurrentRoute(this, settings, targetService)
            if (route.shouldStartLocalBridge) {
                LocalProxyService.startSafely(this, targetService.key)
                var waited = 0
                while (
                    (LocalProxyService.activePort() == null ||
                        LocalProxyService.activeChainSpec() != route.upstreamChainSpec) &&
                    waited < 1200
                ) {
                    try { Thread.sleep(60) } catch (_: InterruptedException) { break }
                    waited += 60
                }
                route = GeoBypassEngine.resolveCurrentRoute(this, settings, targetService)
            }
            postUi {
                setBusy(false)
                if (route.shouldStartDastyabVpn && !DastyabVpnService.isConnected()) {
                    postOutput(getString(R.string.main_starting_tunnel_log, settings.mode.localizedLabel(this), serviceName) + "\n")
                    requestStartVpn(serviceName, url)
                } else {
                    if (route.externalVpnActive) {
                        postOutput(getString(R.string.main_external_vpn_kept_log) + "\n")
                    } else if (route.webViewHttpProxyPort != null) {
                        postOutput(getString(R.string.main_internal_proxy_used_log, route.routeLabel) + "\n")
                    }
                    verifyAndOpenGoogleService(serviceName, url, route)
                }
            }
        }
    }

    /**
     * Smart AI Studio / Flow launcher: verifies BOTH egress country (strict per-service rules)
     * and real deep HTTPS + geo-gate + app-shell reachability before opening.
     */
    private fun verifyAndOpenGoogleService(
        serviceName: String,
        url: String,
        resolvedRoute: GeoBypassEngine.RouteResolution? = null
    ) {
        setBusy(true)
        postStatus(getString(R.string.main_verifying_service, serviceName))
        setStatusDot(DotState.ORANGE)
        postOutput(getString(R.string.main_verifying_service_log, serviceName, url) + "\n")

        thread(isDaemon = true, name = "dastyab-verify-google") {
            val targetService = GeoBypassEngine.TargetService.fromUrl(url)
            val route = resolvedRoute ?: GeoBypassEngine.resolveCurrentRoute(this, targetService = targetService)
            val probe = GeoBypassEngine.runAccessProbe(route, timeoutMs = 4000)
            val targetOk = probe.targetReady(targetService)

            postUi {
                setBusy(false)
                val ccTag = probe.egress?.countryCode ?: "??"
                if (targetOk) {
                    val lat = if (targetService == GeoBypassEngine.TargetService.GOOGLE_FLOW) probe.flow.latencyMs else probe.aiStudio.latencyMs
                    tvReachabilityBadge.text = "$serviceName ✓ ($ccTag · ${lat}ms · ${probe.routeLabel})"
                    postOutput(getString(R.string.main_service_verified_log, serviceName, probe.routeLabel, ccTag, probe.egress?.ip ?: "") + "\n")
                    openBrowserUrl(serviceName, url)
                } else {
                    val reason = when {
                        probe.egress == null ->
                            "Public egress country verification failed (geo-safety unconfirmed)"
                        targetService == GeoBypassEngine.TargetService.GOOGLE_FLOW && !probe.flowCountrySupported ->
                            getString(R.string.main_geo_blocked_reason, ccTag)
                        targetService == GeoBypassEngine.TargetService.GOOGLE_FLOW && probe.flow.unsupportedRegion ->
                            getString(R.string.main_flow_unsupported_reason, ccTag)
                        targetService == GeoBypassEngine.TargetService.GOOGLE_FLOW -> probe.flow.detail
                        !probe.aiStudioCountrySupported ->
                            "Country $ccTag is geo-blocked for Google AI Studio"
                        else -> probe.aiStudio.detail
                    }
                    tvReachabilityBadge.text = getString(R.string.main_service_blocked_badge, serviceName, ccTag)
                    postOutput(getString(R.string.main_service_check_failed_log, serviceName, probe.routeLabel, reason) + "\n")
                    postStatus(getString(R.string.main_service_geo_issue_status, serviceName))
                    setStatusDot(DotState.RED)
                    UiSafety.safeShowDialog(
                        this,
                        AlertDialog.Builder(this)
                            .setTitle(probe.headline)
                            .setMessage(
                                getString(
                                    R.string.main_service_blocked_message,
                                    probe.routeLabel,
                                    probe.egress?.ip ?: getString(R.string.main_ip_unknown),
                                    ccTag,
                                    reason,
                                    probe.recommendation
                                )
                            )
                            .setPositiveButton(getString(R.string.main_btn_auto_chain_service, serviceName)) { _, _ ->
                                autoChainAndOpenGoogleService(
                                    serviceName = serviceName,
                                    url = url,
                                    targetService = targetService,
                                    excludedIps = setOfNotNull(probe.egress?.ip),
                                    excludedChainSpecs = setOfNotNull(route.upstreamChainSpec.takeIf { it.isNotBlank() })
                                )
                            }
                            .setNeutralButton(getString(R.string.main_btn_open_anyway)) { _, _ ->
                                openBrowserUrl(serviceName, url)
                            }
                            .setNegativeButton(getString(R.string.main_btn_route_proxy_modes)) { _, _ ->
                                GoogleAccessSheet.show(this, serviceName, url) { refreshVpnCard() }
                            }
                    )
                }
            }
        }
    }

    /**
     * Independent "Flow Warrior (Brutal Eagle)" launcher completely isolated from AI Studio.
     * Proactively runs FlowWarriorEngine against Flow's harsh geo-blocks and opens Flow on conquest.
     */
    private fun runFlowWarriorAndOpen(
        excludedIps: Set<String> = emptySet(),
        excludedChainSpecs: Set<String> = emptySet(),
        excludeCurrentRoute: Boolean = false
    ) {
        if (operation.get() != null) return
        if (!flowWarriorInFlight.compareAndSet(false, true)) return
        setBusy(true)
        simpleProgress.visibility = View.VISIBLE
        tvSimpleStepLine.visibility = View.VISIBLE
        val warriorRunning = getString(R.string.flow_warrior_running)
        tvSimpleStepLine.text = warriorRunning
        tvSimpleReachability.text = warriorRunning
        tvReachabilityBadge.text = warriorRunning
        postStatus(warriorRunning)
        setStatusDot(DotState.ORANGE)
        applyFormattedOutput("\n=== ⚔ ${FlowWarriorEngine.WARRIOR_TITLE} ===\n")

        thread(isDaemon = true, name = "dastyab-flow-warrior") {
            val report = try {
                FlowWarriorEngine.runFlowWarriorAutopilot(
                    context = this,
                    excludedEgressIps = excludedIps,
                    excludedChainSpecs = excludedChainSpecs,
                    excludeCurrentRoute = excludeCurrentRoute
                ) { step ->
                    postOutput("$step\n")
                    postUi {
                        if (UiSafety.isActivityAlive(this)) {
                            tvSimpleStepLine.text = step.take(96)
                        }
                    }
                }
            } finally {
                flowWarriorInFlight.set(false)
            }
            if (report.conquered && DastyabVpnService.isConnected()) {
                DastyabVpnService.start(this)
            }
            postUi {
                setBusy(false)
                simpleProgress.visibility = View.GONE
                refreshVpnCard()
                refreshBrainDrawer()
                val ccTag = report.exitCountry ?: "??"
                if (report.conquered) {
                    val msg = getString(R.string.flow_warrior_conquered, ccTag, report.latencyMs)
                    tvSimpleReachability.text = msg
                    tvReachabilityBadge.text = msg
                    tvSimpleStepLine.text = report.headline
                    postStatus(report.headline)
                    setStatusDot(DotState.GREEN)
                    openBrowserUrl(FlowWarriorEngine.WARRIOR_TITLE, CommandCompat.FLOW_URL)
                } else {
                    val failBadge = "${FlowWarriorEngine.WARRIOR_BADGE_PREFIX} ✗ ($ccTag)"
                    tvSimpleReachability.text = failBadge
                    tvReachabilityBadge.text = failBadge
                    tvSimpleStepLine.text = report.headline
                    postStatus(report.headline)
                    setStatusDot(DotState.RED)
                    UiSafety.safeShowDialog(
                        this,
                        AlertDialog.Builder(this)
                            .setTitle(report.headline)
                            .setMessage("Exit tested: ${report.exitIp ?: "-"} ($ccTag)\n\n${report.recommendation}")
                            .setPositiveButton(getString(R.string.flow_warrior_retry_btn)) { _, _ ->
                                runFlowWarriorAndOpen(
                                    excludedIps = setOfNotNull(report.exitIp),
                                    excludedChainSpecs = setOfNotNull(report.chainSpec.takeIf { it.isNotBlank() }),
                                    excludeCurrentRoute = true
                                )
                            }
                            .setNeutralButton(getString(R.string.main_btn_route_proxy_modes)) { _, _ ->
                                GoogleAccessSheet.show(this, FlowWarriorEngine.WARRIOR_TITLE, CommandCompat.FLOW_URL) {
                                    refreshVpnCard()
                                }
                            }
                            .setNegativeButton(getString(R.string.main_btn_open_anyway)) { _, _ ->
                                openBrowserUrl(FlowWarriorEngine.WARRIOR_TITLE, CommandCompat.FLOW_URL)
                            }
                    )
                }
            }
        }
    }

    private fun autoChainAndOpenGoogleService(
        serviceName: String,
        url: String,
        targetService: GeoBypassEngine.TargetService,
        excludedIps: Set<String> = emptySet(),
        excludedChainSpecs: Set<String> = emptySet()
    ) {
        if (targetService == GeoBypassEngine.TargetService.GOOGLE_FLOW) {
            runFlowWarriorAndOpen(
                excludedIps = excludedIps,
                excludedChainSpecs = excludedChainSpecs,
                excludeCurrentRoute = excludedIps.isNotEmpty() || excludedChainSpecs.isNotEmpty()
            )
            return
        }
        if (operation.get() != null) return
        setBusy(true)
        simpleProgress.visibility = View.VISIBLE
        postStatus(getString(R.string.browser_auto_chain_running, serviceName))
        setStatusDot(DotState.ORANGE)
        applyFormattedOutput("\n=== 🦁 ${BrutalAntiGeoblockEngine.LION_TITLE} ($serviceName) ===\n")

        thread(isDaemon = true, name = "dastyab-auto-chain-service") {
            val result = BrutalAntiGeoblockEngine.unleashLionForAiStudio(
                context = this,
                excludedEgressIps = excludedIps,
                excludeCurrentRoute = excludedIps.isNotEmpty() || excludedChainSpecs.isNotEmpty(),
                excludedChainSpecs = excludedChainSpecs
            ) { step ->
                postOutput("$step\n")
            }
            if (result.success && DastyabVpnService.isConnected()) {
                DastyabVpnService.start(this)
            }
            postUi {
                setBusy(false)
                simpleProgress.visibility = View.GONE
                refreshVpnCard()
                postOutput("→ ${result.summary}\n")
                if (result.success) {
                    val ccTag = result.report.egress?.countryCode ?: "??"
                    tvReachabilityBadge.text = "$serviceName ✓ ($ccTag · ${result.bestChainLabel})"
                    tvSimpleReachability.text = "$serviceName ✓ ($ccTag · ${result.bestChainLabel})"
                    postStatus(result.summary)
                    setStatusDot(DotState.GREEN)
                    openBrowserUrl(serviceName, url)
                } else {
                    postStatus(getString(R.string.browser_auto_chain_failed, serviceName))
                    setStatusDot(DotState.RED)
                    UiSafety.safeShowDialog(
                        this,
                        AlertDialog.Builder(this)
                            .setTitle(result.report.headline)
                            .setMessage("${result.summary}\n\n${result.report.recommendation}")
                            .setPositiveButton(getString(R.string.main_btn_route_proxy_modes)) { _, _ ->
                                GoogleAccessSheet.show(this, serviceName, url) { refreshVpnCard() }
                            }
                            .setNeutralButton(getString(R.string.main_btn_open_anyway)) { _, _ ->
                                openBrowserUrl(serviceName, url)
                            }
                            .setNegativeButton(android.R.string.ok, null)
                    )
                }
            }
        }
    }

    private fun selectAutopilotIntent(intent: AutopilotBrain.AutopilotIntent) {
        AutopilotBrain.saveIntent(this, intent)
        refreshIntentChips(intent)
        refreshBrainDrawer()
    }

    private fun refreshIntentChips(activeIntent: AutopilotBrain.AutopilotIntent) {
        styleQuickModeChip(btnIntentBalanced, activeIntent == AutopilotBrain.AutopilotIntent.BALANCED_WEB)
        styleQuickModeChip(btnIntentAiStudio, activeIntent == AutopilotBrain.AutopilotIntent.AI_STUDIO)
        styleQuickModeChip(btnIntentFlow, activeIntent == AutopilotBrain.AutopilotIntent.GOOGLE_FLOW)
        styleQuickModeChip(btnIntentBlackout, activeIntent == AutopilotBrain.AutopilotIntent.BLACKOUT_SURVIVAL)
    }

    private fun refreshBrainDrawer() {
        val snap = AutopilotBrain.getSessionSnapshot()
        val watchdog = FailoverWatchdog.getSnapshot()
        val netKey = AutopilotBrain.detectNetworkContextKey(this)
        val quarantined = AutopilotBrain.countQuarantined(netKey)
        val standby = AutopilotBrain.loadStandbyUris(this).size
        val topScores = snap.topScoredLines.take(3).joinToString(" | ").ifBlank { getString(R.string.simple_brain_empty) }
        val regionTag = if (watchdog.fastestRegionLabel.isNotBlank()) " · ${watchdog.fastestRegionLabel}" else ""
        val ewmaTag = if (watchdog.ewmaLatencyMs > 0L) " · EWMA ${watchdog.ewmaLatencyMs}ms" else ""
        val activeLabel = snap.activeArmLabel.ifBlank { watchdog.lastSummary } + ewmaTag + regionTag
        tvSimpleBrainDetails.text = getString(
            R.string.simple_brain_summary_fmt,
            netKey,
            activeLabel,
            standby,
            quarantined,
            watchdog.nextIntervalSeconds,
            topScores
        )
    }

    /**
     * 1-Tap Zero-Dialog Autopilot: senses network context, races protocol-diverse routes
     * with Happy Eyeballs v2 + Contextual UCB1/EWMA Bandits, updates live 3-step stepper UI,
     * and unlocks inline quick-launch actions without blocking popups on success.
     */
    private fun runNewbieAutopilot() {
        if (operation.get() != null) return
        val chosenIntent = AutopilotBrain.getSavedIntent(this)
        setBusy(true)
        btnNewbieAutopilot.isEnabled = false
        btnSimpleMagicAutopilot.isEnabled = false
        simpleProgress.visibility = View.VISIBLE
        simpleConnectedActions.visibility = View.GONE
        tvSimpleStepLine.visibility = View.VISIBLE
        tvSimpleStepLine.text = getString(R.string.simple_step_sensing)
        postStatus(getString(R.string.autopilot_status_running))
        setStatusDot(DotState.ORANGE)
        val runningText = getString(R.string.autopilot_badge_running)
        tvReachabilityBadge.text = runningText
        tvSimpleReachability.text = runningText
        applyFormattedOutput("\n=== DASTYAB 1-TAP AUTOPILOT (${chosenIntent.name}) ===\n")

        thread(isDaemon = true, name = "dastyab-newbie-autopilot") {
            val report = NewbieAutopilot.run(
                context = this,
                onStep = { step ->
                    postOutput("$step\n")
                    val snap = AutopilotBrain.getSessionSnapshot()
                    postUi {
                        if (!UiSafety.isActivityAlive(this)) return@postUi
                        val label = when (snap.stepIndex) {
                            1 -> getString(R.string.simple_step_sensing)
                            2 -> getString(R.string.simple_step_racing)
                            3 -> getString(R.string.simple_step_verifying)
                            else -> snap.stepHeadline.ifBlank { runningText }
                        }
                        tvSimpleStepLine.text = label
                    }
                },
                intent = chosenIntent
            )
            postUi {
                setBusy(false)
                btnNewbieAutopilot.isEnabled = true
                btnSimpleMagicAutopilot.isEnabled = true
                simpleProgress.visibility = View.GONE
                refreshVpnCard()
                refreshBrainDrawer()

                val v = report.verification
                val webMark = if (v.internet.isOk) "Web ✓" else "Web ✗"
                val badge = if (chosenIntent == AutopilotBrain.AutopilotIntent.GOOGLE_FLOW) {
                    val flowMark = if (v.flow.isOk) "${FlowWarriorEngine.WARRIOR_BADGE_PREFIX} ✓" else "${FlowWarriorEngine.WARRIOR_BADGE_PREFIX} ✗"
                    "$webMark · $flowMark"
                } else {
                    val aiMark = if (v.aiStudio.isOk) "AI Studio ✓" else "AI Studio ✗"
                    "$webMark · $aiMark"
                }
                tvReachabilityBadge.text = badge
                tvSimpleReachability.text = badge
                tvSimpleStepLine.visibility = View.VISIBLE
                tvSimpleStepLine.text = report.headline

                postStatus(report.headline)
                setStatusDot(
                    when (report.outcome) {
                        NewbieAutopilot.Outcome.READY_DIRECT,
                        NewbieAutopilot.Outcome.READY_WITH_VPN -> DotState.GREEN
                        NewbieAutopilot.Outcome.NEEDS_VPN_CONSENT,
                        NewbieAutopilot.Outcome.NEEDS_FULL_PROXY_APP -> DotState.ORANGE
                        NewbieAutopilot.Outcome.OFFLINE_OR_BLACKOUT -> DotState.RED
                    }
                )

                when (report.outcome) {
                    NewbieAutopilot.Outcome.READY_DIRECT,
                    NewbieAutopilot.Outcome.READY_WITH_VPN -> {
                        // Zero-Dialog happy path: show inline action buttons directly inside the Hero Card
                        simpleConnectedActions.visibility = View.VISIBLE
                        DastyabWidgetProvider.updateAllWidgets(this)
                    }
                    NewbieAutopilot.Outcome.NEEDS_VPN_CONSENT -> {
                        // Trigger OS VPN permission directly with zero extra confirmation popup
                        requestStartVpn(null, null)
                    }
                    NewbieAutopilot.Outcome.NEEDS_FULL_PROXY_APP -> {
                        val dialog = AlertDialog.Builder(this)
                            .setTitle(report.headline)
                            .setMessage(report.summary)
                        val bestUri = report.bestHarvestedUri
                        val firstApp = report.installedProxyApps.firstOrNull()
                        if (bestUri != null) {
                            dialog.setPositiveButton(
                                if (firstApp != null) getString(R.string.autopilot_copy_and_open, firstApp.name)
                                else getString(R.string.autopilot_copy_fastest)
                            ) { _, _ ->
                                if (UiSafety.copyTextSafely(this, "DastYab Fastest Config", bestUri)) {
                                    Toast.makeText(this, getString(R.string.autopilot_fastest_copied), Toast.LENGTH_LONG).show()
                                }
                                firstApp?.installedPackage?.let { pkg ->
                                    packageManager.getLaunchIntentForPackage(pkg)?.let {
                                        UiSafety.safeStartActivity(this, it)
                                    }
                                }
                            }
                        }
                        dialog.setNeutralButton(getString(R.string.autopilot_open_rescue_hub)) { _, _ -> openRescueHub() }
                        dialog.setNegativeButton(android.R.string.ok, null)
                        UiSafety.safeShowDialog(this, dialog)
                    }
                    NewbieAutopilot.Outcome.OFFLINE_OR_BLACKOUT -> {
                        val dialog = AlertDialog.Builder(this)
                            .setTitle(report.headline)
                            .setMessage(report.summary)
                            .setPositiveButton(getString(R.string.autopilot_open_blackout_rescue)) { _, _ ->
                                openRescueHub(BlackoutRescueActivity.ACTION_TROUBLESHOOT)
                            }
                            .setNegativeButton(android.R.string.ok, null)
                        UiSafety.safeShowDialog(this, dialog)
                    }
                }
            }
        }
    }

    private fun openBrowserUrl(serviceName: String, url: String) {
        postOutput(getString(R.string.main_opening_browser_log, serviceName) + "\n")
        postStatus(getString(R.string.main_opening_browser_status, serviceName))
        setStatusDot(DotState.ORANGE)
        try {
            InAppBrowserActivity.launch(this, serviceName, url)
            val vpnNote = if (DastyabVpnService.isConnected()) " (${getString(R.string.main_vpn_active_note)})" else ""
            postOutput(getString(R.string.main_browser_opened_log, serviceName, vpnNote, url) + "\n")
            postStatus(getString(R.string.main_browser_opened_status, serviceName, vpnNote))
            setStatusDot(DotState.GREEN)
        } catch (_: Exception) {
            try {
                startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url)))
            } catch (_: android.content.ActivityNotFoundException) {
                postOutput(getString(R.string.main_no_browser_log, url) + "\n")
                postStatus(getString(R.string.main_no_browser_status))
                setStatusDot(DotState.RED)
            }
        }
    }

    private fun showImportVlessDialog() {
        val input = EditText(this).apply {
            hint = getString(R.string.tunnel_vless_hint)
            setText(TunnelConfig.load(this@MainActivity).vlessUri)
            setSingleLine(false)
            maxLines = 4
        }
        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(getString(R.string.vpn_btn_import_vless))
                .setView(input)
                .setPositiveButton(android.R.string.ok) { _, _ ->
                    val uri = input.text.toString().trim()
                    val parsed = TunnelConfig.parseVlessUri(uri)
                    if (uri.isEmpty()) {
                        TunnelConfig.saveVlessUri(this, "")
                        refreshVpnCard()
                        postOutput("Cleared custom VLESS endpoint (using Cloudflare Edge Smart DNS).\n")
                    } else if (parsed == null) {
                        Toast.makeText(this, getString(R.string.tunnel_vless_invalid), Toast.LENGTH_SHORT).show()
                    } else {
                        TunnelConfig.saveVlessUri(this, uri)
                        refreshVpnCard()
                        postOutput("OK: Imported VLESS endpoint → ${parsed.summary()} (SNI: ${parsed.sni})\n")
                        if (DastyabVpnService.isConnected()) {
                            DastyabVpnService.start(this)
                        }
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
        )
    }

    private fun refreshVpnCard() {
        if (!UiSafety.isActivityAlive(this)) return
        val statusObj = DastyabVpnService.getStatus()
        val settings = TunnelConfig.load(this)
        val externalVpn = NetworkUtils.hasActiveExternalVpn(this)
        val bridgePort = LocalProxyService.activePort()
        val activeMode = if (statusObj.state == DastyabVpnService.State.CONNECTED) statusObj.mode else settings.mode

        when {
            statusObj.state == DastyabVpnService.State.CONNECTED -> {
                setViewHalo(vpnDot, StatusHaloView.HaloState.CONNECTED, R.drawable.status_dot_green)
                setViewHalo(simpleStatusDot, StatusHaloView.HaloState.CONNECTED, R.drawable.status_dot_green)
                tvVpnState.text = "${getString(R.string.vpn_status_connected)} · ${activeMode.localizedLabel(this)}"
                tvSimpleHeroTitle.text = getString(R.string.simple_hero_connected)
                btnVpnToggle.text = getString(R.string.vpn_btn_disconnect)
                btnSimpleQuickToggle.text = getString(R.string.vpn_btn_disconnect)
            }
            statusObj.state == DastyabVpnService.State.CONNECTING -> {
                setViewHalo(vpnDot, StatusHaloView.HaloState.CONNECTING, R.drawable.status_dot_orange)
                setViewHalo(simpleStatusDot, StatusHaloView.HaloState.CONNECTING, R.drawable.status_dot_orange)
                tvVpnState.text = getString(R.string.vpn_status_connecting)
                tvSimpleHeroTitle.text = getString(R.string.vpn_status_connecting)
                btnVpnToggle.text = getString(R.string.vpn_btn_disconnect)
                btnSimpleQuickToggle.text = getString(R.string.vpn_btn_disconnect)
            }
            externalVpn || bridgePort != null -> {
                setViewHalo(vpnDot, StatusHaloView.HaloState.CONNECTED, R.drawable.status_dot_green)
                setViewHalo(simpleStatusDot, StatusHaloView.HaloState.CONNECTED, R.drawable.status_dot_green)
                val extLabel = when {
                    externalVpn && bridgePort != null -> getString(R.string.main_external_vpn_plus_proxy, bridgePort)
                    externalVpn -> getString(R.string.main_external_vpn_active)
                    else -> getString(R.string.main_local_proxy_active, bridgePort ?: 0)
                }
                tvVpnState.text = extLabel
                tvSimpleHeroTitle.text = extLabel
                btnVpnToggle.text = getString(R.string.vpn_btn_connect)
                btnSimpleQuickToggle.text = getString(R.string.vpn_btn_connect)
            }
            else -> {
                setViewHalo(vpnDot, StatusHaloView.HaloState.IDLE, R.drawable.status_dot_gray)
                setViewHalo(simpleStatusDot, StatusHaloView.HaloState.IDLE, R.drawable.status_dot_gray)
                tvVpnState.text = "${getString(R.string.vpn_status_disconnected)} · ${activeMode.localizedLabel(this)}"
                tvSimpleHeroTitle.text = getString(R.string.simple_hero_disconnected)
                btnVpnToggle.text = getString(R.string.vpn_btn_connect)
                btnSimpleQuickToggle.text = getString(R.string.vpn_btn_connect)
            }
        }

        val endpoint = when {
            activeMode == TunnelConfig.Mode.DNS_BLACKOUT -> "DoH (${settings.dohUrl.removePrefix("https://")})"
            else -> settings.parsedEndpoint()?.summary() ?: "Cloudflare Edge Smart DNS"
        }
        val splitSuffix = if (activeMode == TunnelConfig.Mode.SPLIT_INCLUDE || activeMode == TunnelConfig.Mode.SPLIT_EXCLUDE) {
            " · ${settings.splitPackages.size} app(s)"
        } else {
            ""
        }
        val iranBypassTag = if (DomainDnsRules.load(this).iranBypassEnabled) " · .ir Bypass" else ""
        val watchdogSnap = FailoverWatchdog.getSnapshot()
        val watchdogTag = if (statusObj.state == DastyabVpnService.State.CONNECTED && watchdogSnap.active) {
            val rttNote = if (watchdogSnap.ewmaLatencyMs > 0L) " · ${watchdogSnap.ewmaLatencyMs}ms" else ""
            val blackoutNote = if (watchdogSnap.autoBlackoutEscalated) " · BlackoutVPN" else ""
            " · ${watchdogSnap.nextIntervalSeconds}s Auto-Heal$rttNote$blackoutNote"
        } else {
            ""
        }
        val proxyTag = when {
            bridgePort != null -> " · LocalPort :$bridgePort"
            settings.upstreamProxyScheme != TunnelConfig.ProxyScheme.DIRECT ->
                " · ${settings.upstreamProxyScheme.name}:${settings.upstreamProxyPort}"
            else -> ""
        }
        tvVpnDetails.text = "$endpoint · DNS ${settings.dnsPrimary}$splitSuffix$iranBypassTag$watchdogTag$proxyTag"
        if (statusObj.state == DastyabVpnService.State.CONNECTED || externalVpn) {
            simpleConnectedActions.visibility = View.VISIBLE
        } else if (operation.get() == null && AutopilotBrain.getSessionSnapshot().phase != AutopilotBrain.SessionPhase.CONNECTED) {
            simpleConnectedActions.visibility = View.GONE
        }
        if (simpleBrainDrawer.visibility == View.VISIBLE) {
            refreshBrainDrawer()
        }

        // Highlight active quick-mode chip cleanly
        val isSplit = activeMode == TunnelConfig.Mode.SPLIT_INCLUDE || activeMode == TunnelConfig.Mode.SPLIT_EXCLUDE
        styleQuickModeChip(btnModeSmart, activeMode == TunnelConfig.Mode.SMART)
        styleQuickModeChip(btnModeGlobal, activeMode == TunnelConfig.Mode.GLOBAL)
        styleQuickModeChip(btnModeSplit, isSplit)
        styleQuickModeChip(btnModeDns, activeMode == TunnelConfig.Mode.DNS_BLACKOUT)
    }

    private fun styleQuickModeChip(chip: Button, active: Boolean) {
        chip.alpha = 1.0f
        chip.background = getDrawable(if (active) R.drawable.tab_active_bg else R.drawable.tab_inactive_bg)
        chip.setTextColor(
            if (active) ThemeManager.resolveColor(this, R.attr.dastyabButtonPrimaryText, R.color.colorButtonPrimaryText)
            else ThemeManager.resolveColor(this, R.attr.dastyabTextSecondary, R.color.colorTextSecondary)
        )
    }

    private fun openActivity(type: Class<out Activity>) {
        try { startActivity(Intent(this, type)) }
        catch (_: android.content.ActivityNotFoundException) { postStatus("Screen unavailable") }
    }

    /** Switches between Simple Mode, Advanced Mode, and Terminal Mode (CPython 3.11) with smooth choreography. */
    private fun applyUiMode(mode: UiModePrefs.Mode, persist: Boolean = true) {
        val previous = when {
            simpleModeContainer.visibility == View.VISIBLE -> UiModePrefs.Mode.SIMPLE
            advancedModeContainer.visibility == View.VISIBLE -> UiModePrefs.Mode.ADVANCED
            else -> UiModePrefs.Mode.TERMINAL
        }
        if (persist) UiModePrefs.setMode(this, mode)
        val slideDir = mode.ordinal - previous.ordinal
        val target = when (mode) {
            UiModePrefs.Mode.SIMPLE -> simpleModeContainer
            UiModePrefs.Mode.ADVANCED -> advancedModeContainer
            UiModePrefs.Mode.TERMINAL -> terminalModeContainer
        }
        val others = listOf(simpleModeContainer, advancedModeContainer, terminalModeContainer)
        if (persist) {
            DastyabMotion.switchModeContainer(target, others, slideDir)
        } else {
            simpleModeContainer.visibility = if (mode == UiModePrefs.Mode.SIMPLE) View.VISIBLE else View.GONE
            advancedModeContainer.visibility = if (mode == UiModePrefs.Mode.ADVANCED) View.VISIBLE else View.GONE
            terminalModeContainer.visibility = if (mode == UiModePrefs.Mode.TERMINAL) View.VISIBLE else View.GONE
        }

        styleSegmentedTab(btnTabSimple, mode == UiModePrefs.Mode.SIMPLE)
        styleSegmentedTab(btnTabAdvanced, mode == UiModePrefs.Mode.ADVANCED)
        styleSegmentedTab(btnTabTerminal, mode == UiModePrefs.Mode.TERMINAL)

        if (mode == UiModePrefs.Mode.TERMINAL) {
            initTerminalSessionIfNeeded()
        }
    }

    private fun styleSegmentedTab(tab: Button, active: Boolean) {
        tab.alpha = 1.0f
        tab.background = getDrawable(if (active) R.drawable.tab_active_bg else R.drawable.tab_inactive_bg)
        tab.setTextColor(
            if (active) ThemeManager.resolveColor(this, R.attr.dastyabButtonPrimaryText, R.color.colorButtonPrimaryText)
            else ThemeManager.resolveColor(this, R.attr.dastyabTextSecondary, R.color.colorTextSecondary)
        )
    }

    private fun setupTerminalModeUi() {
        buildTerminalPresetChips(R.id.terminalChipsFlow, TerminalCommandRouter.PYTHON_FLOW_PRESETS)
        buildTerminalPresetChips(R.id.terminalChipsShell, TerminalCommandRouter.LINUX_PYTHON_PRESETS)

        btnTerminalRun.setOnClickListener {
            runTerminalCommand(terminalInput.text.toString())
        }
        btnTerminalStop.setOnClickListener { cancelTerminalCommand() }
        findViewById<Button>(R.id.btnTerminalClear).setOnClickListener {
            tvTerminalOutput.text = ""
        }
        findViewById<Button>(R.id.btnTerminalCopy).setOnClickListener {
            if (UiSafety.copyTextSafely(this, "Dastyab Terminal", tvTerminalOutput.text.toString())) {
                Toast.makeText(this, getString(R.string.copied_to_clipboard), Toast.LENGTH_SHORT).show()
            }
        }
        findViewById<Button>(R.id.btnTerminalSyncNodes).setOnClickListener {
            thread(isDaemon = true, name = "dastyab-term-sync") {
                val count = PythonRuntimeBridge.syncProfile(this)
                postUi {
                    appendTerminalOutput("[sync] Synced $count node(s) + active route into ~/.dastyab/profiles/default/\n")
                }
            }
        }
        findViewById<Button>(R.id.btnTerminalPackages).setOnClickListener {
            showTerminalPackagesDialog()
        }
        findViewById<Button>(R.id.btnTerminalOpenAiStudio).setOnClickListener {
            launchGoogleServiceViaVpn(getString(R.string.service_name_aistudio), CommandCompat.AISTUDIO_URL)
        }
        findViewById<Button>(R.id.btnTerminalOpenFlow).setOnClickListener {
            launchGoogleServiceViaVpn(getString(R.string.service_name_flow), CommandCompat.FLOW_URL)
        }
        terminalInput.setOnEditorActionListener { _, actionId, _ ->
            if (actionId == EditorInfo.IME_ACTION_SEND || actionId == EditorInfo.IME_ACTION_DONE) {
                runTerminalCommand(terminalInput.text.toString())
                true
            } else {
                false
            }
        }
    }

    private fun showTerminalPackagesDialog() {
        appendTerminalOutput("[pip] Inspecting bundled & user Python packages…\n")
        thread(isDaemon = true, name = "dastyab-pip-summary") {
            val raw = PythonRuntimeBridge.getPipSummaryJson(this)
            val doc = runCatching { JSONObject(raw) }.getOrNull() ?: JSONObject()
            val total = doc.optInt("total_installed", 0)
            val missingArr = doc.optJSONArray("missing_recommended")
            val missingList = buildList {
                if (missingArr != null) {
                    for (i in 0 until missingArr.length()) {
                        val s = missingArr.optString(i, "")
                        if (s.isNotBlank()) add(s)
                    }
                }
            }
            val recArr = doc.optJSONArray("recommended")
            val statusLines = StringBuilder()
            if (recArr != null) {
                for (i in 0 until recArr.length()) {
                    val item = recArr.optJSONObject(i) ?: continue
                    val mark = if (item.optBoolean("installed", false)) "✓" else "✗"
                    val name = item.optString("name", "")
                    val ver = item.optString("version", "")
                    val src = item.optString("source", "")
                    val detail = if (ver.isNotBlank()) "$ver ($src)" else "not installed"
                    statusLines.append("$mark $name — $detail\n")
                }
            }
            postUi {
                val summary = if (statusLines.isNotEmpty()) {
                    "Installed distributions: $total\n" +
                        "Missing recommended: ${if (missingList.isEmpty()) "None (all ready)" else missingList.joinToString(", ")}\n\n" +
                        statusLines.toString().trimEnd()
                } else {
                    "Manage Python packages in ~/.dastyab/site-packages.\n" +
                        "Note: Core pure-Python packages (requests, certifi, PySocks, dnspython, beautifulsoup4) are pre-bundled; tap below to install/update all recommended packages or install custom PyPI packages."
                }
                UiSafety.safeShowDialog(
                    this,
                    AlertDialog.Builder(this)
                        .setTitle("Python Packages (pip)")
                        .setMessage(summary)
                        .setPositiveButton("Install All Recommended") { _, _ ->
                            runTerminalCommand("pip install --recommended")
                        }
                        .setNeutralButton("Install Custom…") { _, _ ->
                            showCustomPipInstallDialog()
                        }
                        .setNegativeButton("pip check") { _, _ ->
                            runTerminalCommand("pip check")
                        }
                )
            }
        }
    }

    private fun showCustomPipInstallDialog() {
        val input = EditText(this).apply {
            hint = "pyyaml httpx rich colorama"
            setSingleLine(true)
        }
        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle("pip install <packages>")
                .setMessage("Enter pure-Python PyPI package name(s) separated by spaces or commas:")
                .setView(input)
                .setPositiveButton("Install") { _, _ ->
                    val cmd = TerminalCommandRouter.buildPipInstallCommand(input.text.toString())
                    if (cmd == null) {
                        Toast.makeText(this, "Enter valid PyPI package names", Toast.LENGTH_SHORT).show()
                    } else {
                        runTerminalCommand(cmd)
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
        )
    }

    private fun buildTerminalPresetChips(containerId: Int, presets: List<TerminalCommandRouter.QuickPreset>) {
        val container = findViewById<LinearLayout>(containerId)
        presets.forEach { preset ->
            val chip = Button(this, null, 0, R.style.DastyabChip).apply {
                text = preset.label
                setOnClickListener {
                    if (!terminalRunning.get()) {
                        terminalInput.setText(preset.command)
                        if (preset.autoRun) {
                            runTerminalCommand(preset.command)
                        }
                    }
                }
            }
            DastyabMotion.attachPressSpring(chip)
            container.addView(chip)
        }
    }

    private fun initTerminalSessionIfNeeded() {
        if (terminalBannerShown) return
        terminalBannerShown = true
        appendTerminalOutput("Booting embedded CPython 3.11 Linux-compatible shell...\n")
        thread(isDaemon = true, name = "dastyab-cpython-boot") {
            val ver = PythonRuntimeBridge.getPythonVersion(this)
            val synced = PythonRuntimeBridge.syncProfile(this)
            val cwd = PythonRuntimeBridge.getPromptPath(this)
            postUi {
                tvTerminalRuntimeBadge.text = ver
                tvTerminalPromptHeader.text = TerminalCommandRouter.formatPrompt(cwd).trimEnd()
                appendTerminalOutput(
                    "Ready: $ver | Synced $synced node(s) to ~/.dastyab/profiles/default/\n" +
                        "Run `dastyab flow best`, `dastyab flow start`, `dastyab aistudio verify`, `pip install --recommended`, or `python3 -c \"...\"`.\n\n"
                )
            }
        }
    }

    private fun runTerminalCommand(rawCommand: String) {
        if (!terminalRunning.compareAndSet(false, true)) return
        val cmd = TerminalCommandRouter.normalizeInput(rawCommand)
        when (TerminalCommandRouter.classify(cmd)) {
            TerminalCommandRouter.Action.EMPTY -> {
                terminalRunning.set(false)
                return
            }
            TerminalCommandRouter.Action.CLEAR -> {
                tvTerminalOutput.text = ""
                terminalInput.setText("")
                terminalRunning.set(false)
                return
            }
            TerminalCommandRouter.Action.PYTHON_SHELL -> { /* execute */ }
        }

        val currentPrompt = tvTerminalPromptHeader.text.toString()
        appendTerminalOutput("$currentPrompt $cmd\n")
        terminalInput.setText("")
        setTerminalBusy(true)

        thread(isDaemon = true, name = "dastyab-cpython-exec") {
            val exitCode = try {
                PythonRuntimeBridge.executeCommand(
                    context = this,
                    commandLine = cmd,
                    callbacks = object : PythonRuntimeBridge.HostCallbacks {
                        override fun onStdout(text: String) {
                            postUi { appendTerminalOutput(text) }
                        }

                        override fun onEvent(kind: String, payloadJson: String) {
                            postUi { handleTerminalHostEvent(kind, payloadJson) }
                        }

                        override fun runNativeCli(args: List<String>, outputCallback: (String) -> Unit): Int {
                            return PythonRuntimeBridge.execNativeBinary(
                                context = this@MainActivity,
                                binary = binary,
                                args = args,
                                onChunk = outputCallback,
                                processHolder = terminalProcessHolder
                            )
                        }
                    }
                )
            } finally {
                terminalRunning.set(false)
            }
            val nextCwd = PythonRuntimeBridge.getPromptPath(this)
            postUi {
                setTerminalBusy(false)
                tvTerminalPromptHeader.text = TerminalCommandRouter.formatPrompt(nextCwd).trimEnd()
                if (exitCode != 0) {
                    appendTerminalOutput("[exit $exitCode]\n")
                }
                refreshVpnCard()
            }
        }
    }

    private fun cancelTerminalCommand() {
        PythonRuntimeBridge.requestStop(this)
        terminalProcessHolder.get()?.let { terminate(it) }
        appendTerminalOutput("\n^C Stop requested\n")
    }

    private fun setTerminalBusy(busy: Boolean) {
        btnTerminalRun.isEnabled = !busy
        terminalInput.isEnabled = !busy
        btnTerminalStop.visibility = if (busy) View.VISIBLE else View.GONE
        terminalProgress.visibility = if (busy) View.VISIBLE else View.GONE
    }

    private fun appendTerminalOutput(text: String) {
        tvTerminalOutput.append(formatOutput(text))
        if (tvTerminalOutput.length() > MAX_OUTPUT_CHARS) {
            val full = tvTerminalOutput.text
            tvTerminalOutput.text = full.subSequence(full.length - MAX_OUTPUT_CHARS, full.length)
        }
        terminalOutputScroll.post {
            terminalOutputScroll.fullScroll(View.FOCUS_DOWN)
        }
    }

    private fun handleTerminalHostEvent(kind: String, payloadJson: String) {
        val obj = runCatching { JSONObject(payloadJson) }.getOrNull() ?: JSONObject()
        when (kind) {
            "CLEAR_TERMINAL" -> tvTerminalOutput.text = ""
            "OPEN_BROWSER" -> {
                val url = obj.optString("url", CommandCompat.FLOW_URL)
                val title = obj.optString("title", "DastYab Browser")
                openBrowserUrl(title, url)
            }
            "SYNC_SERVICE_CHAIN" -> {
                val targetService = obj.optString("target_service", "").trim().lowercase()
                val rawChain = obj.optJSONArray("chain")
                val hops = ArrayList<TunnelConfig.ProxyHop>()
                if (rawChain != null) {
                    for (i in 0 until rawChain.length()) {
                        val item = rawChain.optJSONObject(i) ?: continue
                        val scheme = when (item.optString("scheme", "").trim().lowercase()) {
                            "http" -> TunnelConfig.ProxyScheme.HTTP
                            "socks5" -> TunnelConfig.ProxyScheme.SOCKS5
                            else -> null
                        } ?: continue
                        val host = item.optString("host", "").trim()
                        val port = item.optInt("port", 0)
                        if (host.isNotEmpty() && port in 1..65535) {
                            hops.add(
                                TunnelConfig.ProxyHop(
                                    scheme = scheme,
                                    host = host,
                                    port = port,
                                    username = item.optString("username", ""),
                                    password = item.optString("password", "")
                                )
                            )
                        }
                    }
                }
                if (targetService == "aistudio" || targetService == "flow") {
                    TunnelConfig.saveServiceProxyChain(
                        context = this,
                        targetServiceKey = targetService,
                        hops = hops,
                        preserveExternalVpn = true
                    )
                    if (hops.isNotEmpty()) {
                        LocalProxyService.startSafely(this, targetService)
                    }
                    val label = obj.optString("label", "${hops.size}-hop route")
                    appendTerminalOutput("[android] Synced $targetService chain ($label) to DastYab Browser.\n")
                    refreshVpnCard()
                }
            }
            "SYNC_BEST_VLESS" -> {
                val uri = obj.optString("uri", "")
                if (uri.startsWith("vless://", ignoreCase = true)) {
                    val cur = TunnelConfig.load(this)
                    if (cur.vlessUri.isBlank()) {
                        TunnelConfig.saveVlessUri(this, uri)
                        appendTerminalOutput("[android] Synced fastest VLESS endpoint to active profile.\n")
                    }
                }
            }
        }
    }

    /** 1-tap Speed, Exit Country/Geo & separated AI Studio / Google Flow live check from Simple Mode. */
    private fun runQuickSpeedAndIpCheck() {
        simpleProgress.visibility = View.VISIBLE
        tvSimpleReachability.text = getString(R.string.main_speed_checking)
        thread(isDaemon = true, name = "dastyab-quick-speed") {
            val settings = TunnelConfig.load(this)
            val aiRoute = GeoBypassEngine.resolveCurrentRoute(this, settings, GeoBypassEngine.TargetService.AI_STUDIO)
            val flowRoute = GeoBypassEngine.resolveCurrentRoute(this, settings, GeoBypassEngine.TargetService.GOOGLE_FLOW)
            val aiProbe = GeoBypassEngine.runAccessProbe(aiRoute, timeoutMs = 4000)
            val flowProbe = if (flowRoute.upstreamChainSpec == aiRoute.upstreamChainSpec && flowRoute.javaNetProxy == aiRoute.javaNetProxy) {
                aiProbe
            } else {
                GeoBypassEngine.runAccessProbe(flowRoute, timeoutMs = 4000)
            }
            postUi {
                simpleProgress.visibility = View.GONE
                val egress = flowProbe.egress ?: aiProbe.egress
                val ccMark = if (egress != null) {
                    if (flowProbe.flowCountrySupported) "${egress.countryCode} ✓" else "${egress.countryCode} ✗"
                } else "Geo ?"
                val aiMark = if (aiProbe.readyForAiStudio) "AI Studio ✓" else "AI Studio ✗"
                val flowMark = if (flowProbe.readyForFlow) "Flow ✓" else "Flow ✗"
                val badge = "$ccMark · $aiMark · $flowMark"
                tvSimpleReachability.text = badge
                tvReachabilityBadge.text = badge
                setStatusDot(
                    when {
                        aiProbe.readyForAiStudio && flowProbe.readyForFlow -> DotState.GREEN
                        aiProbe.readyForAiStudio || flowProbe.readyForFlow -> DotState.ORANGE
                        else -> DotState.RED
                    }
                )

                val blockedFlowIps = setOfNotNull(flowProbe.egress?.ip?.takeIf { !flowProbe.readyForFlow })
                val blockedFlowChains = setOfNotNull(flowRoute.upstreamChainSpec.takeIf { it.isNotBlank() && !flowProbe.readyForFlow })

                val msg = getString(
                    R.string.lantern_dialog_dual_body,
                    if (aiProbe.readyForAiStudio) "READY ✓ (${aiProbe.aiStudio.detail})" else "BLOCKED ✗ (${aiProbe.aiStudio.detail})",
                    aiProbe.routeLabel,
                    if (flowProbe.readyForFlow) "READY ✓ (${flowProbe.flow.detail})" else "BLOCKED ✗ (${flowProbe.flow.detail})",
                    flowProbe.routeLabel,
                    egress?.ip ?: getString(R.string.main_ip_unknown),
                    egress?.countryCode ?: "??",
                    if (flowProbe.flowCountrySupported) getString(R.string.main_geo_flow_supported) else getString(R.string.main_geo_flow_blocked),
                    flowProbe.recommendation
                )
                val title = when {
                    aiProbe.readyForAiStudio && flowProbe.readyForFlow -> "AI Studio ✓ & Flow ✓ (${egress?.countryCode ?: "?"})"
                    aiProbe.readyForAiStudio -> "AI Studio ✓ · Flow Geo-Blocked ✗"
                    else -> flowProbe.headline
                }
                UiSafety.safeShowDialog(
                    this,
                    AlertDialog.Builder(this)
                        .setTitle(title)
                        .setMessage(msg)
                        .setPositiveButton(getString(R.string.main_btn_route_proxy_modes)) { _, _ ->
                            GoogleAccessSheet.show(this) { refreshVpnCard() }
                        }
                        .setNeutralButton(getString(R.string.main_btn_auto_chain_service, getString(R.string.service_name_flow))) { _, _ ->
                            autoChainAndOpenGoogleService(
                                serviceName = getString(R.string.service_name_flow),
                                url = CommandCompat.FLOW_URL,
                                targetService = GeoBypassEngine.TargetService.GOOGLE_FLOW,
                                excludedIps = blockedFlowIps,
                                excludedChainSpecs = blockedFlowChains
                            )
                        }
                        .setNegativeButton(android.R.string.ok, null)
                )
            }
        }
    }

    /** Show the advanced (raw command) section smoothly. */
    private fun showAdvanced() {
        DastyabMotion.revealPanel(advancedSection)
        btnShowAdvanced.visibility = View.GONE
    }

    /** Hide the advanced (raw command) section. */
    private fun hideAdvanced() {
        advancedSection.visibility = View.GONE
        DastyabMotion.revealPanel(btnShowAdvanced)
    }

    /** Run a predefined simple action command (no typing). */
    private fun runSimple(label: String, args: List<String>) {
        CommandHistory.add(label)
        setupHistorySpinner()
        applyFormattedOutput("\n\$ dastyab ${args.joinToString(" ")}\n---\n")
        setBusy(true)
        postStatus("Running…")
        setStatusDot(DotState.ORANGE)

        when (val verdict = CommandCompat.check(args)) {
            is CommandCompat.Verdict.OpenAistudio -> {
                setBusy(false)
                launchGoogleServiceViaVpn("Google AI Studio", verdict.url)
                return
            }
            is CommandCompat.Verdict.OpenFlow -> {
                setBusy(false)
                launchGoogleServiceViaVpn("Google Flow", verdict.url)
                return
            }
            is CommandCompat.Verdict.Blocked -> {
                postStatus(CommandCompat.blockedTitle(verdict))
                postOutput(CommandCompat.blockedMessage(verdict) + "\n")
                setStatusDot(DotState.RED)
                setBusy(false)
                return
            }
            CommandCompat.Verdict.RunNative -> { /* proceed */ }
        }

        if (!binary.isFile || !binary.canExecute()) {
            setBusy(false)
            evaluateBinaryState()
            return
        }
        runCommand(args, label)
    }

    override fun onSaveInstanceState(outState: Bundle) {
        super.onSaveInstanceState(outState)
        outState.putString("pendingOutput", output.text.toString())
    }

    override fun onDestroy() {
        if (vpnReceiverRegistered) {
            try { unregisterReceiver(vpnStateReceiver) } catch (_: Exception) {}
            vpnReceiverRegistered = false
        }
        synchronized(uiLock) {
            destroyed = true
            handler.removeCallbacksAndMessages(null)
        }
        cancelCurrentOperation()
        cancelTerminalCommand()
        super.onDestroy()
    }

    private fun evaluateBinaryState() {
        val ready = binary.isFile && binary.canExecute() && BinaryUtils.isValidElfBinary(binary)
        btnRun.isEnabled = ready
        postStatus(if (ready) getString(R.string.status_ready)
            else "Bundled CLI unavailable for this device. Install a compatible APK from Releases.")
        setStatusDot(if (ready) DotState.GREEN else DotState.RED)
    }

    private fun runTyped() {
        if (operation.get() != null) return
        val text = argsInput.text.toString()
        if (text.length > MAX_ARGS_LENGTH) {
            postStatus(getString(R.string.error_args_too_long))
            return
        }
        val args = try { CommandArgs.parse(text) } catch (e: IllegalArgumentException) {
            postStatus(e.message ?: "Invalid arguments")
            return
        }
        if (args.isEmpty()) return
        when (val verdict = CommandCompat.check(args)) {
            is CommandCompat.Verdict.OpenAistudio -> {
                launchGoogleServiceViaVpn("Google AI Studio", verdict.url)
                return
            }
            is CommandCompat.Verdict.OpenFlow -> {
                launchGoogleServiceViaVpn("Google Flow", verdict.url)
                return
            }
            is CommandCompat.Verdict.Blocked -> {
                postStatus(CommandCompat.blockedTitle(verdict))
                postOutput(CommandCompat.blockedMessage(verdict) + "\n")
                setStatusDot(DotState.RED)
                setBusy(false)
                return
            }
            CommandCompat.Verdict.RunNative -> { /* proceed to run the binary */ }
        }
        if (!binary.isFile || !binary.canExecute()) {
            evaluateBinaryState()
            return
        }
        runCommand(args, text)
    }

    private fun buildQuickButtons(containerId: Int, commands: List<String>) {
        val container = findViewById<LinearLayout>(containerId)
        commands.forEach { command ->
            val chip = Button(this, null, 0, R.style.DastyabChip).apply {
                text = command
                setOnClickListener {
                    if (operation.get() == null) {
                        argsInput.setText(command)
                        runTyped()
                    }
                }
            }
            DastyabMotion.attachPressSpring(chip)
            container.addView(chip)
        }
    }

    private fun setupHistorySpinner() {
        val items = listOf(getString(R.string.history_prompt)) + CommandHistory.getCommands()
        historySpinner.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, items).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }
        historySpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                if (position > 0 && operation.get() == null) argsInput.setText(items[position])
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }
    }

    private fun applyPersistedSettings() {
        val prefs = getSharedPreferences(SettingsActivity.PREFS_NAME, Context.MODE_PRIVATE)
        prefs.getString(SettingsActivity.PREF_LOG_LEVEL, null)?.let {
            try { DastyabLogger.setMinFileLevel(DastyabLogger.LogLevel.valueOf(it)) }
            catch (_: IllegalArgumentException) { }
        }
    }

    private fun cancelCurrentOperation() {
        operation.get()?.let { current ->
            current.cancelled.set(true)
            current.process.get()?.let { terminate(it) }
        }
    }

    private fun terminate(process: Process) {
        process.destroy()
        if (Build.VERSION.SDK_INT >= 26) process.destroyForcibly()
    }

    // Timed Process.waitFor is API 26; polling exitValue also supports API 24/25.
    private fun awaitExit(process: Process): Boolean {
        val deadline = System.nanoTime() + TimeUnit.MILLISECONDS.toNanos(PROCESS_TIMEOUT_MS)
        while (true) {
            try {
                process.exitValue()
                return true
            } catch (_: IllegalThreadStateException) { }
            if (System.nanoTime() >= deadline) return false
            Thread.sleep(50)
        }
    }

    /** A timed wait runs independently of the output reader, even for a silent child. */
    private fun runCommand(args: List<String>, commandText: String) {
        val current = Operation()
        if (!operation.compareAndSet(null, current)) return
        CommandHistory.add(commandText)
        setupHistorySpinner()
        applyFormattedOutput("\n\$ dastyab $commandText\n---\n")
        setBusy(true)
        postStatus("Running…")
        setStatusDot(DotState.ORANGE)
        val command = listOf(binary.absolutePath) + args
        val home = filesDir
        val temporary = cacheDir.absolutePath
        thread(isDaemon = true, name = "dastyab-command") {
            var process: Process? = null
            var readerThread: Thread? = null
            var result = "Command failed"
            var success = false
            try {
                if (!current.cancelled.get()) {
                    val child = ProcessBuilder(command).apply {
                        directory(home)
                        environment()["HOME"] = home.absolutePath
                        environment()["TMPDIR"] = temporary
                        redirectErrorStream(true)
                    }.start()
                    process = child
                    current.process.set(child)
                    if (current.cancelled.get()) terminate(child)
                    child.outputStream.close()
                    readerThread = thread(isDaemon = true, name = "dastyab-output") {
                        try {
                            child.inputStream.reader(Charsets.UTF_8).use { reader ->
                                val buffer = CharArray(4096)
                                while (true) {
                                    val count = reader.read(buffer)
                                    if (count < 0) break
                                    postOutput(String(buffer, 0, count))
                                }
                            }
                        } catch (_: java.io.IOException) {
                            // Closing the child during cancellation/timeout ends the reader.
                        }
                    }
                    if (!awaitExit(child)) {
                        result = "Command timed out after ${PROCESS_TIMEOUT_MS / 1000} seconds"
                        terminate(child)
                    } else {
                        val code = child.exitValue()
                        result = "--- exit code $code ---"
                        success = code == 0
                    }
                }
            } catch (e: Exception) {
                result = "ERROR: ${e.message ?: e.javaClass.simpleName}"
                DastyabLogger.e("Run", e, "Command failed")
            } finally {
                process?.let { child ->
                    runCatching { terminate(child) }
                    runCatching { readerThread?.join(1000) }
                    runCatching { child.inputStream.close() }
                    runCatching { child.errorStream.close() }
                    runCatching { child.outputStream.close() }
                }
                current.process.set(null)
                if (current.cancelled.get()) {
                    result = "Command cancelled."
                    success = false
                }
                val finalResult = result
                val finalSuccess = success
                postUi {
                    applyFormattedOutput("\n$finalResult\n")
                    status.text = finalResult
                    setStatusDot(if (finalSuccess) DotState.GREEN else DotState.RED)
                    operation.compareAndSet(current, null)
                    setBusy(false)
                }
                synchronized(uiLock) {
                    if (destroyed) operation.compareAndSet(current, null)
                }
            }
        }
    }

    /** Enqueue and teardown use the same lock: no callbacks can be added after teardown. */
    private fun postUi(action: () -> Unit) {
        synchronized(uiLock) {
            if (!destroyed && UiSafety.isActivityAlive(this)) handler.post {
                synchronized(uiLock) {
                    if (!destroyed && UiSafety.isActivityAlive(this)) {
                        try {
                            action()
                        } catch (t: Throwable) {
                            DastyabLogger.e("MainActivity", t, "Suppressed UI callback error")
                        }
                    }
                }
            }
        }
    }

    private fun postStatus(message: String) = postUi { status.text = message }
    private fun postOutput(message: String) = postUi { applyFormattedOutput(message) }

    private fun applyFormattedOutput(message: String) {
        outputEmptyState.visibility = View.GONE
        if (output.visibility != View.VISIBLE) {
            DastyabMotion.revealPanel(output)
        }
        output.append(formatOutput(message))
        if (output.length() > MAX_OUTPUT_CHARS) {
            output.text = output.text.subSequence(output.length() - MAX_OUTPUT_CHARS, output.length())
        }
        output.movementMethod = android.text.method.LinkMovementMethod.getInstance()
    }

    fun formatOutput(text: String): Spannable {
        val spans = SpannableStringBuilder(text)
        var offset = 0
        for (line in text.split('\n')) {
            val lower = line.trimStart().lowercase()
            val color = when {
                lower.startsWith("error") -> ThemeManager.resolveColor(this, R.attr.dastyabStatusError, R.color.colorStatusError)
                lower.startsWith("warn") -> ThemeManager.resolveColor(this, R.attr.dastyabStatusWarning, R.color.colorStatusWarning)
                lower.startsWith("ok") || lower.startsWith("success") -> ThemeManager.resolveColor(this, R.attr.dastyabStatusReady, R.color.colorStatusReady)
                else -> null
            }
            if (color != null) spans.setSpan(
                ForegroundColorSpan(color),
                offset,
                offset + line.length,
                Spannable.SPAN_EXCLUSIVE_EXCLUSIVE
            )
            if (Regex("""^---\s*exit code\s+-?\d+\s*---$""", RegexOption.IGNORE_CASE)
                    .matches(line.trim())) {
                spans.setSpan(
                    StyleSpan(Typeface.BOLD),
                    offset,
                    offset + line.length,
                    Spannable.SPAN_EXCLUSIVE_EXCLUSIVE
                )
            }
            Regex("https?://[^\\s]+").findAll(line).forEach { match ->
                val url = match.value
                spans.setSpan(object : ClickableSpan() {
                    override fun onClick(widget: View) {
                        try { startActivity(Intent(Intent.ACTION_VIEW, Uri.parse(url))) }
                        catch (_: android.content.ActivityNotFoundException) { }
                    }
                }, offset + match.range.first, offset + match.range.last + 1, Spannable.SPAN_EXCLUSIVE_EXCLUSIVE)
            }
            offset += line.length + 1
        }
        return spans
    }

    private enum class DotState { GREEN, ORANGE, RED }

    private fun setViewHalo(view: View, haloState: StatusHaloView.HaloState, fallbackDrawableRes: Int) {
        if (view is StatusHaloView) {
            view.setHaloState(haloState)
        } else {
            view.background = getDrawable(fallbackDrawableRes)
        }
    }

    private fun setStatusDot(state: DotState) {
        when (state) {
            DotState.GREEN -> setViewHalo(statusDot, StatusHaloView.HaloState.CONNECTED, R.drawable.status_dot_green)
            DotState.ORANGE -> setViewHalo(statusDot, StatusHaloView.HaloState.CONNECTING, R.drawable.status_dot_orange)
            DotState.RED -> setViewHalo(statusDot, StatusHaloView.HaloState.ERROR, R.drawable.status_dot_red)
        }
    }

    private fun setBusy(busy: Boolean) {
        btnRun.isEnabled = !busy && binary.isFile && binary.canExecute()
        argsInput.isEnabled = !busy
        btnCancel.visibility = if (busy) View.VISIBLE else View.GONE
        progress.isIndeterminate = true
        progress.visibility = if (busy) View.VISIBLE else View.GONE
    }
}
