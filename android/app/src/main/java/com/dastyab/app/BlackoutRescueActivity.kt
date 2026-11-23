package com.dastyab.app

import android.app.AlertDialog
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.Uri
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * BlackoutRescueActivity — DastYab's resilient anti-censorship & blackout rescue hub.
 *
 * Combines:
 *  1. 5-Stage Resilient Config Harvester (GitHub Direct → jsDelivr Mirror → Telegram →
 *     Alternate VPN Detection → Temporary Bootstrap Config → Emergency DNS Blackout)
 *  2. Full Emergency DNS Blackout VPN (WhiteDNS / DoH / SlipNet)
 *  3. On-Device IP Range & Clean DNS/DoH Scout (IP-Range-Scout-Android style)
 *  4. 7-Point Smart Connectivity Troubleshooter with tailored Rescue Plan
 *  5. Installed Fallback VPN Launcher & Official GitHub Links (WhiteDNS, WhiteVPN,
 *     IP Range Scout, SlipNet, ShiroKhorshid, Lantern, Tor/Orbot, v2rayNG, Hiddify, NekoBox, Psiphon, WARP)
 */
class BlackoutRescueActivity : DastyabActivity() {

    companion object {
        const val EXTRA_AUTO_ACTION = "extra_auto_action"
        const val ACTION_HARVEST = "harvest"
        const val ACTION_SCOUT = "scout"
        const val ACTION_TROUBLESHOOT = "troubleshoot"
        const val ACTION_DNS_VPN = "dns_vpn"
        private const val REQ_VPN_BLACKOUT = 5001
        private const val REQ_OPEN_CONFIG_FILE = 5002
    }

    private lateinit var progress: ProgressBar
    private lateinit var tvHarvestSummary: TextView
    private lateinit var tvDiagnosisHeadline: TextView
    private lateinit var tvRescueLog: TextView
    private lateinit var spinnerDohPreset: Spinner
    private lateinit var etDnsTunnelDomain: EditText
    private lateinit var fallbackToolsContainer: LinearLayout

    private val handler = Handler(Looper.getMainLooper())
    private val busy = AtomicBoolean(false)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_blackout_rescue)

        progress = findViewById(R.id.rescueProgress)
        tvHarvestSummary = findViewById(R.id.tvHarvestSummary)
        tvDiagnosisHeadline = findViewById(R.id.tvDiagnosisHeadline)
        tvRescueLog = findViewById(R.id.tvRescueLog)
        spinnerDohPreset = findViewById(R.id.spinnerDohPreset)
        etDnsTunnelDomain = findViewById(R.id.etDnsTunnelDomain)
        fallbackToolsContainer = findViewById(R.id.fallbackToolsContainer)

        setupDohSpinner()
        refreshHarvestSummary()
        populateFallbackTools()

        findViewById<Button>(R.id.btnRunHarvest).setOnClickListener { runSmartHarvest() }
        findViewById<Button>(R.id.btnPickHarvested).setOnClickListener { showHarvestedConfigsDialog() }
        findViewById<Button>(R.id.btnOpenFileVault).setOnClickListener { showConfigFileVaultDialog() }
        findViewById<Button>(R.id.btnOpenSourceManager).setOnClickListener {
            startActivity(Intent(this, SourceManagerActivity::class.java))
        }
        findViewById<Button>(R.id.btnSetBootstrap).setOnClickListener { showBootstrapConfigDialog() }
        findViewById<Button>(R.id.btnActivateDnsBlackout).setOnClickListener { activateDnsBlackoutVpn() }
        findViewById<Button>(R.id.btnScoutEdgeIps).setOnClickListener { runEdgeIpScout() }
        findViewById<Button>(R.id.btnScoutCleanDns).setOnClickListener { runCleanDnsScout() }
        findViewById<Button>(R.id.btnRunTroubleshoot).setOnClickListener { runTroubleshooter() }
        findViewById<Button>(R.id.btnRescueBack).setOnClickListener { finish() }

        when (intent?.getStringExtra(EXTRA_AUTO_ACTION)) {
            ACTION_HARVEST -> runSmartHarvest()
            ACTION_SCOUT -> runEdgeIpScout()
            ACTION_TROUBLESHOOT -> runTroubleshooter()
            ACTION_DNS_VPN -> activateDnsBlackoutVpn()
        }
    }

    private fun setupDohSpinner() {
        val settings = TunnelConfig.load(this)
        val labels = CleanEndpointScout.DOH_PRESETS.map { "${it.name} · ${it.bootstrapIp}" }
        spinnerDohPreset.adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, labels).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }
        val selectedIdx = CleanEndpointScout.DOH_PRESETS.indexOfFirst {
            it.url.equals(settings.dohUrl, ignoreCase = true)
        }.coerceAtLeast(0)
        spinnerDohPreset.setSelection(selectedIdx)
        etDnsTunnelDomain.setText(settings.dnsTunnelDomain)
    }

    private fun refreshHarvestSummary() {
        val cached = TunnelConfig.loadHarvestedConfigs(this)
        val vaultFiles = ConfigFileHarvester.loadVault(this)
        val settings = TunnelConfig.load(this)
        val bootstrapNote = if (settings.bootstrapConfig.isNotBlank()) getString(R.string.rescue_bootstrap_saved_tag) else ""
        val fileNote = if (vaultFiles.isNotEmpty()) " · ${vaultFiles.size} files (.txt/.ovpn/.npvs/.hc/…)" else ""
        tvHarvestSummary.text = if (cached.isEmpty() && vaultFiles.isEmpty()) {
            getString(R.string.rescue_harvester_hint) + bootstrapNote
        } else {
            getString(R.string.rescue_cached_summary, cached.size, bootstrapNote) + fileNote
        }
    }

    private fun populateFallbackTools() {
        fallbackToolsContainer.removeAllViews()
        val tools = ConfigHarvester.detectFallbackTools(this)
        // Show installed tools first so the user can launch them immediately
        val sorted = tools.sortedByDescending { it.isInstalled }
        for (tool in sorted) {
            val btn = Button(this, null, 0, R.style.DastyabButton).apply {
                val badge = if (tool.isInstalled) getString(R.string.rescue_tool_installed) else "GitHub"
                text = "${tool.name} (${tool.category}) · $badge"
                setOnClickListener {
                    if (tool.isInstalled && tool.installedPackage != null) {
                        val launch = packageManager.getLaunchIntentForPackage(tool.installedPackage)
                        if (launch != null && UiSafety.safeStartActivity(this@BlackoutRescueActivity, launch)) {
                            Toast.makeText(
                                this@BlackoutRescueActivity,
                                getString(R.string.rescue_tool_launch_toast, tool.name),
                                Toast.LENGTH_LONG
                            ).show()
                        } else {
                            openExternalUrl(tool.githubUrl)
                        }
                    } else {
                        openExternalUrl(tool.githubUrl)
                    }
                }
            }
            val params = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = (8 * resources.displayMetrics.density).toInt()
            }
            fallbackToolsContainer.addView(btn, params)
        }
    }

    private fun runSmartHarvest() {
        if (!busy.compareAndSet(false, true)) return
        setLoading(true)
        clearLog("Starting 5-stage resilient config harvest…\n")

        thread(isDaemon = true, name = "dastyab-harvest") {
            val report = ConfigHarvester.harvestResilient(this) { line ->
                appendLog("$line\n")
            }
            UiSafety.safePostUi(this, handler) {
                setLoading(false)
                busy.set(false)
                refreshHarvestSummary()
                appendLog("\n=== RESULT: ${report.outcome.name} ===\n${report.guidance}\n")
                when (report.outcome) {
                    ConfigHarvester.HarvestOutcome.SUCCESS_GITHUB,
                    ConfigHarvester.HarvestOutcome.SUCCESS_TELEGRAM,
                    ConfigHarvester.HarvestOutcome.SUCCESS_MIXED -> {
                        Toast.makeText(this, getString(R.string.rescue_harvested_toast, report.configs.size), Toast.LENGTH_SHORT).show()
                        if (report.configs.isNotEmpty()) {
                            showHarvestedConfigsDialog()
                        } else {
                            showConfigFileVaultDialog()
                        }
                    }
                    ConfigHarvester.HarvestOutcome.NEEDS_ALTERNATE_VPN,
                    ConfigHarvester.HarvestOutcome.NEEDS_BOOTSTRAP_CONFIG,
                    ConfigHarvester.HarvestOutcome.BLACKOUT_DNS_ONLY -> {
                        showHarvestFailureRecoveryDialog(report)
                    }
                }
            }
        }
    }

    private fun showHarvestFailureRecoveryDialog(report: ConfigHarvester.HarvestReport) {
        val options = mutableListOf<String>()
        options.add(getString(R.string.rescue_fail_opt_dns_vpn))
        options.add(getString(R.string.rescue_fail_opt_bootstrap))
        options.add(getString(R.string.rescue_fail_opt_scout))
        if (report.installedFallbackTools.isNotEmpty()) {
            options.add(getString(R.string.rescue_fail_opt_fallback, report.installedFallbackTools.first().name))
        }
        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(getString(R.string.rescue_fail_title))
                .setMessage(report.guidance)
                .setItems(options.toTypedArray()) { _, which ->
                    when (which) {
                        0 -> activateDnsBlackoutVpn()
                        1 -> showBootstrapConfigDialog()
                        2 -> runCleanDnsScout()
                        3 -> {
                            val pkg = report.installedFallbackTools.firstOrNull()?.installedPackage
                            if (pkg != null) {
                                packageManager.getLaunchIntentForPackage(pkg)?.let {
                                    UiSafety.safeStartActivity(this, it)
                                }
                            }
                        }
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
        )
    }

    private fun showHarvestedConfigsDialog() {
        val configs = TunnelConfig.loadHarvestedConfigs(this)
        if (configs.isEmpty()) {
            Toast.makeText(this, getString(R.string.rescue_pool_empty_toast), Toast.LENGTH_SHORT).show()
            return
        }
        val labels = configs.mapIndexed { idx, uri ->
            val parsed = UniversalConfig.parse(uri)
            val proto = (parsed?.protocol ?: UniversalConfig.protocolOf(uri)).uppercase()
            val vless = TunnelConfig.parseVlessUri(uri)
            when {
                vless != null -> "${idx + 1}. [$proto] ${vless.summary()}"
                parsed != null -> "${idx + 1}. [$proto] ${parsed.summary()}"
                else -> "${idx + 1}. [$proto] ${uri.take(48)}…"
            }
        }.toTypedArray()

        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(getString(R.string.rescue_pool_title, configs.size))
                .setItems(labels) { _, which ->
                    showHarvestedConfigActionsDialog(which, configs[which])
                }
                .setNegativeButton(android.R.string.cancel, null)
        )
    }

    private fun showHarvestedConfigActionsDialog(index: Int, rawUri: String) {
        val parsed = UniversalConfig.parse(rawUri)
        val proto = (parsed?.protocol ?: UniversalConfig.protocolOf(rawUri)).uppercase()
        val targetLabel = parsed?.let { "${it.host}:${it.port}" } ?: proto
        val isVless = rawUri.startsWith("vless://", ignoreCase = true)
        val wgIni = if (UniversalConfig.isWireGuardUri(rawUri)) UniversalConfig.wireGuardUriToIni(rawUri) else null
        val ovpnProfile = if (UniversalConfig.isOpenVpnUri(rawUri)) UniversalConfig.openVpnUriToOvpn(rawUri) else null
        val isMtProto = UniversalConfig.isMtProtoUri(rawUri)
        val installedTools = ConfigHarvester.detectFallbackTools(this).filter { it.isInstalled }
        val matchingClient = pickMatchingClientTool(proto, installedTools)

        val isRunnableScheme = parsed != null && proto !in setOf("MTPROTO", "UNKNOWN")
        val actions = mutableListOf<Pair<String, () -> Unit>>()
        if (isRunnableScheme) {
            actions.add(getString(R.string.rescue_action_apply_vpn) to {
                TunnelConfig.saveActiveConfigUri(this, rawUri)
                TunnelConfig.saveMode(this, TunnelConfig.Mode.SMART)
                Toast.makeText(this, "Activated [$proto] & starting VPN…", Toast.LENGTH_SHORT).show()
                appendLog("Activated harvested [$proto] #${index + 1} (${targetLabel}) as active endpoint.\n")
                requestStartVpnNow()
            })
            actions.add("Chain Entry (WARP/Proxy) → Exit (PattNG)" to {
                showChainEntryExitDialog(index, rawUri, proto, targetLabel)
            })
        }
        if (isMtProto) {
            actions.add(getString(R.string.rescue_action_open_telegram) to {
                UiSafety.copyTextSafely(this, "Telegram MTProto", rawUri)
                UiSafety.safeStartActivity(this, Intent(Intent.ACTION_VIEW, Uri.parse(rawUri)))
            })
        }
        if (wgIni != null) {
            actions.add(getString(R.string.rescue_action_copy_wg_ini) to {
                if (UiSafety.copyTextSafely(this, "WireGuard Config", wgIni)) {
                    Toast.makeText(this, getString(R.string.rescue_wg_ini_copied_toast), Toast.LENGTH_SHORT).show()
                    appendLog("Copied WireGuard .conf INI for config #${index + 1}.\n")
                }
                TunnelConfig.saveBootstrapConfig(this, rawUri)
                refreshHarvestSummary()
            })
            actions.add(getString(R.string.rescue_action_save_open_file) to {
                val entry = ConfigFileHarvester.saveGeneratedTextFile(
                    this,
                    "dastyab_${parsed?.host ?: "wg"}.conf",
                    wgIni,
                    "WireGuard"
                )
                refreshHarvestSummary()
                ConfigFileHarvester.openVaultFileInExternalApp(this, entry, matchingClient?.installedPackage)
            })
        }
        if (ovpnProfile != null) {
            actions.add(getString(R.string.rescue_action_copy_ovpn) to {
                if (UiSafety.copyTextSafely(this, "OpenVPN Config", ovpnProfile)) {
                    Toast.makeText(this, getString(R.string.rescue_ovpn_copied_toast), Toast.LENGTH_SHORT).show()
                    appendLog("Copied OpenVPN .ovpn profile for config #${index + 1}.\n")
                }
                TunnelConfig.saveBootstrapConfig(this, rawUri)
                refreshHarvestSummary()
            })
            actions.add(getString(R.string.rescue_action_save_open_file) to {
                val entry = ConfigFileHarvester.saveGeneratedTextFile(
                    this,
                    "dastyab_${parsed?.host ?: "ovpn"}.ovpn",
                    ovpnProfile,
                    "OpenVPN"
                )
                refreshHarvestSummary()
                ConfigFileHarvester.openVaultFileInExternalApp(this, entry, matchingClient?.installedPackage)
            })
        }
        actions.add(getString(R.string.rescue_action_promote_layer) to {
            val layerName = parsed?.label?.takeIf { it.isNotBlank() }
                ?: "$proto ${parsed?.host ?: "#${index + 1}"}"
            val layer = VpnLayerStore.VpnLayer(
                id = "harvest-${proto.lowercase()}-${(parsed?.host ?: "node").hashCode()}",
                name = layerName,
                mode = TunnelConfig.Mode.SMART,
                configUri = rawUri
            )
            VpnLayerStore.addOrUpdate(this, layer)
            VpnLayerStore.activateLayer(this, layer, restartIfConnected = isRunnableScheme)
            refreshHarvestSummary()
            Toast.makeText(this, getString(R.string.rescue_layer_promoted_toast, proto), Toast.LENGTH_SHORT).show()
            appendLog("Saved harvested [$proto] config #${index + 1} as VPN layer '$layerName'.\n")
        })
        actions.add(getString(R.string.rescue_action_copy_uri) to {
            if (UiSafety.copyTextSafely(this, "DastYab $proto Config", rawUri)) {
                Toast.makeText(this, getString(R.string.rescue_copied_proto_toast, proto), Toast.LENGTH_SHORT).show()
            }
            TunnelConfig.saveBootstrapConfig(this, rawUri)
            refreshHarvestSummary()
            appendLog("Copied harvested [$proto] config #${index + 1} to clipboard.\n")
        })
        if (matchingClient != null && matchingClient.installedPackage != null) {
            actions.add(getString(R.string.rescue_action_open_client, matchingClient.name) to {
                val copyPayload = wgIni ?: ovpnProfile ?: rawUri
                UiSafety.copyTextSafely(this, "DastYab $proto Config", copyPayload)
                TunnelConfig.saveBootstrapConfig(this, rawUri)
                packageManager.getLaunchIntentForPackage(matchingClient.installedPackage)?.let {
                    UiSafety.safeStartActivity(this, it)
                }
            })
        }

        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(getString(R.string.rescue_action_title, proto, targetLabel))
                .setItems(actions.map { it.first }.toTypedArray()) { _, actIdx ->
                    actions[actIdx].second.invoke()
                }
                .setNegativeButton(android.R.string.cancel, null)
        )
    }

    private fun pickMatchingClientTool(
        protoOrExtUpper: String,
        installed: List<ConfigHarvester.FallbackTool>
    ): ConfigHarvester.FallbackTool? {
        val preferredNames = when (protoOrExtUpper) {
            "OPENVPN", "OVPN" -> listOf("OpenVPN for Android", "OpenVPN Connect", "Hiddify")
            "WIREGUARD", "WG", "WARP", "AMNEZIAWG", "CONF" -> listOf("WireGuard", "Hiddify", "NekoBox", "NapsternetV")
            "NPV", "NPV4", "NPVS", "NPVT", "NAPSTERNETV" -> listOf("NapsternetV", "Hiddify", "NekoBox")
            "HC" -> listOf("HTTP Custom", "HTTP Injector")
            "EHI", "CUSTOM", "COSTUM" -> listOf("HTTP Injector", "HTTP Custom")
            "DARK" -> listOf("DarkTunnel")
            "HAT" -> listOf("HA Tunnel Plus")
            "TLS" -> listOf("TLS Tunnel")
            "NM" -> listOf("NetMod")
            else -> listOf("v2rayNG", "Hiddify", "NekoBox", "NapsternetV", "WhiteVPN")
        }
        for (name in preferredNames) {
            installed.firstOrNull { it.name.equals(name, ignoreCase = true) }?.let { return it }
        }
        return installed.firstOrNull()
    }

    private fun showConfigFileVaultDialog() {
        val vault = ConfigFileHarvester.loadVault(this)
        val entries = mutableListOf<String>()
        entries.add(getString(R.string.rescue_vault_btn_download_url))
        entries.add(getString(R.string.rescue_vault_btn_import_local))
        vault.forEach { entries.add(it.label()) }

        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(getString(R.string.rescue_vault_title, vault.size))
                .setItems(entries.toTypedArray()) { _, which ->
                    when (which) {
                        0 -> showDownloadConfigFileUrlDialog()
                        1 -> launchLocalConfigFilePicker()
                        else -> showVaultFileActionsDialog(vault[which - 2])
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
        )
    }

    private fun showDownloadConfigFileUrlDialog() {
        val input = EditText(this).apply {
            hint = getString(R.string.rescue_vault_download_hint)
        }
        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(getString(R.string.rescue_vault_download_title))
                .setView(input)
                .setPositiveButton(android.R.string.ok) { _, _ ->
                    val url = input.text.toString().trim()
                    if (!url.startsWith("http://", true) && !url.startsWith("https://", true)) {
                        Toast.makeText(this, getString(R.string.rescue_vault_download_fail), Toast.LENGTH_SHORT).show()
                        return@setPositiveButton
                    }
                    setLoading(true)
                    thread(isDaemon = true, name = "dastyab-dl-cfg") {
                        val (entry, extracted) = ConfigFileHarvester.downloadAndStoreFile(this, url, sourceLabel = "Manual URL")
                        if (extracted.isNotEmpty()) {
                            val merged = UniversalConfig.mergeBalanced(TunnelConfig.loadHarvestedConfigs(this) + extracted, 4096)
                            TunnelConfig.saveHarvestedConfigs(this, merged)
                        }
                        UiSafety.safePostUi(this, handler) {
                            setLoading(false)
                            refreshHarvestSummary()
                            if (entry != null) {
                                Toast.makeText(this, getString(R.string.rescue_vault_download_ok, entry.fileName), Toast.LENGTH_SHORT).show()
                                showVaultFileActionsDialog(entry)
                            } else {
                                Toast.makeText(this, getString(R.string.rescue_vault_download_fail), Toast.LENGTH_SHORT).show()
                            }
                        }
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
        )
    }

    private fun launchLocalConfigFilePicker() {
        val picker = Intent(Intent.ACTION_OPEN_DOCUMENT).apply {
            addCategory(Intent.CATEGORY_OPENABLE)
            type = "*/*"
        }
        try {
            @Suppress("DEPRECATION")
            startActivityForResult(picker, REQ_OPEN_CONFIG_FILE)
        } catch (_: Exception) {
            Toast.makeText(this, getString(R.string.rescue_vault_import_fail), Toast.LENGTH_SHORT).show()
        }
    }

    private fun showVaultFileActionsDialog(entry: ConfigFileHarvester.VaultEntry) {
        val installedTools = ConfigHarvester.detectFallbackTools(this).filter { it.isInstalled }
        val match = pickMatchingClientTool(entry.extension.uppercase(), installedTools)
        val actions = mutableListOf<Pair<String, () -> Unit>>()

        if (entry.isDownloadedLocally) {
            if (match != null && match.installedPackage != null) {
                actions.add(getString(R.string.rescue_vault_file_open_client, match.name) to {
                    ConfigFileHarvester.openVaultFileInExternalApp(this, entry, match.installedPackage)
                })
            }
            actions.add(getString(R.string.rescue_vault_file_open_any) to {
                ConfigFileHarvester.openVaultFileInExternalApp(this, entry, null)
            })
            actions.add(getString(R.string.rescue_vault_file_save_downloads) to {
                val ok = ConfigFileHarvester.exportToDownloads(this, entry)
                val msg = if (ok) getString(R.string.rescue_vault_saved_downloads_toast, entry.fileName)
                else getString(R.string.rescue_vault_download_fail)
                Toast.makeText(this, msg, Toast.LENGTH_LONG).show()
            })
            actions.add(getString(R.string.rescue_vault_file_extract_promote) to {
                val bytes = runCatching { java.io.File(entry.localPath).readBytes() }.getOrDefault(ByteArray(0))
                val extracted = ConfigFileHarvester.extractEndpointsFromFileBytes(entry.fileName, bytes)
                if (extracted.isEmpty()) {
                    Toast.makeText(this, getString(R.string.rescue_vault_no_endpoints_toast), Toast.LENGTH_SHORT).show()
                } else {
                    val merged = UniversalConfig.mergeBalanced(extracted + TunnelConfig.loadHarvestedConfigs(this), 4096)
                    TunnelConfig.saveHarvestedConfigs(this, merged)
                    val firstUri = extracted.first()
                    val layer = VpnLayerStore.VpnLayer(
                        name = "${entry.extension.uppercase()} · ${entry.fileName}",
                        mode = TunnelConfig.Mode.SMART,
                        configUri = firstUri
                    )
                    VpnLayerStore.addOrUpdate(this, layer)
                    VpnLayerStore.activateLayer(this, layer, restartIfConnected = true)
                    refreshHarvestSummary()
                    appendLog("Extracted ${extracted.size} configs from ${entry.fileName}; active endpoint -> $firstUri\n")
                    Toast.makeText(this, getString(R.string.rescue_vault_import_ok, entry.fileName, extracted.size), Toast.LENGTH_LONG).show()
                }
            })
        }
        val postUrl = entry.postUrl ?: entry.downloadUrl
        if (!postUrl.isNullOrBlank()) {
            actions.add(getString(R.string.rescue_vault_file_open_tg_post) to {
                openExternalUrl(postUrl)
            })
        }

        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(entry.fileName)
                .setItems(actions.map { it.first }.toTypedArray()) { _, idx ->
                    actions[idx].second.invoke()
                }
                .setNegativeButton(android.R.string.cancel, null)
        )
    }

    private fun showChainEntryExitDialog(index: Int, exitUri: String, proto: String, targetLabel: String) {
        val pool = TunnelConfig.loadHarvestedConfigs(this)
        val warpOrProxy = pool.firstOrNull {
            UniversalConfig.protocolOf(it) in setOf("warp", "wireguard", "wg", "amneziawg", "socks5", "socks", "http")
        }.orEmpty()
        val input = EditText(this).apply {
            hint = "Entry URI (warp://..., wg://..., socks5://..., or leave blank for TLS fragment)"
            setText(warpOrProxy)
            setSingleLine(false)
            maxLines = 3
        }
        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle("Chain Entry → Exit ($proto $targetLabel)")
                .setMessage("Pairs a WARP/WireGuard/Proxy Entry hop with Exit #$index using Xray dialerProxy + TLS fragment + uTLS.")
                .setView(input)
                .setPositiveButton("Build Chain & Activate") { _, _ ->
                    val entryUri = input.text.toString().trim().ifEmpty { null }
                    val chainJson = runCatching {
                        UniversalConfig.buildXrayChainConfigJson(entryUri, exitUri)
                    }.getOrNull()
                    if (chainJson == null) {
                        Toast.makeText(this, "Could not build chain JSON for this URI", Toast.LENGTH_SHORT).show()
                        return@setPositiveButton
                    }
                    val savedEntry = ConfigFileHarvester.saveGeneratedTextFile(
                        this,
                        "chain_${proto.lowercase()}_${index + 1}.json",
                        chainJson,
                        "PattNG-Chain"
                    )
                    val layer = VpnLayerStore.VpnLayer(
                        id = "chain-${proto.lowercase()}-$index",
                        name = "Chain → $proto ($targetLabel)",
                        mode = TunnelConfig.Mode.SMART,
                        configUri = exitUri,
                        upstreamProxyChain = entryUri ?: ""
                    )
                    VpnLayerStore.addOrUpdate(this, layer)
                    VpnLayerStore.activateLayer(this, layer, restartIfConnected = true)
                    UiSafety.copyTextSafely(this, "Xray Entry-Exit Chain", chainJson)
                    refreshHarvestSummary()
                    appendLog("Built Entry->Exit Xray chain JSON (${savedEntry.fileName}) and copied to clipboard.\n")
                    requestStartVpnNow()
                }
                .setNegativeButton(android.R.string.cancel, null)
        )
    }

    private fun showBootstrapConfigDialog() {
        val current = TunnelConfig.load(this).bootstrapConfig
        val input = EditText(this).apply {
            hint = getString(R.string.rescue_bootstrap_hint)
            setText(current)
            setSingleLine(false)
            maxLines = 5
        }
        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(getString(R.string.rescue_bootstrap_title))
                .setMessage(getString(R.string.rescue_bootstrap_msg))
                .setView(input)
                .setPositiveButton(getString(R.string.rescue_bootstrap_save_connect)) { _, _ ->
                    val rawCfg = input.text.toString().trim()
                    if (rawCfg.isEmpty()) {
                        TunnelConfig.saveBootstrapConfig(this, "")
                        refreshHarvestSummary()
                        return@setPositiveButton
                    }
                    val normalizedCfg = UniversalConfig.extractAll(rawCfg, maxConfigs = 1).firstOrNull() ?: rawCfg
                    TunnelConfig.saveBootstrapConfig(this, normalizedCfg)
                    refreshHarvestSummary()
                    appendLog("Saved temporary bootstrap config (${UniversalConfig.protocolOf(normalizedCfg).uppercase()}).\n")
                    if (normalizedCfg.startsWith("vless://", ignoreCase = true)) {
                        TunnelConfig.saveMode(this, TunnelConfig.Mode.SMART)
                        requestStartVpnNow()
                    } else {
                        val copyText = UniversalConfig.wireGuardUriToIni(normalizedCfg) ?: normalizedCfg
                        if (UiSafety.copyTextSafely(this, "Bootstrap Config", copyText)) {
                            Toast.makeText(this, getString(R.string.rescue_bootstrap_copied_toast), Toast.LENGTH_LONG).show()
                        }
                    }
                }
                .setNeutralButton(getString(R.string.rescue_btn_paste)) { _, _ ->
                    val clip = runCatching {
                        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
                        cm?.primaryClip?.getItemAt(0)?.coerceToText(this)?.toString().orEmpty()
                    }.getOrDefault("")
                    if (clip.isNotBlank()) {
                        TunnelConfig.saveBootstrapConfig(this, clip)
                        refreshHarvestSummary()
                        Toast.makeText(this, getString(R.string.rescue_bootstrap_pasted_toast), Toast.LENGTH_SHORT).show()
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
        )
    }

    private fun activateDnsBlackoutVpn() {
        val idx = spinnerDohPreset.selectedItemPosition.coerceIn(0, CleanEndpointScout.DOH_PRESETS.lastIndex)
        val preset = CleanEndpointScout.DOH_PRESETS[idx]
        val dnsDomain = etDnsTunnelDomain.text.toString().trim()
        TunnelConfig.saveDohAndDns(this, preset.url, preset.bootstrapIp, dnsDomain)
        TunnelConfig.saveMode(this, TunnelConfig.Mode.DNS_BLACKOUT)
        appendLog("Activating Emergency DNS Blackout VPN → ${preset.name} (UDP fallback: ${preset.bootstrapIp})…\n")
        requestStartVpnNow()
    }

    private fun requestStartVpnNow() {
        val prep = VpnService.prepare(this)
        if (prep != null) {
            try {
                @Suppress("DEPRECATION")
                startActivityForResult(prep, REQ_VPN_BLACKOUT)
            } catch (_: Exception) {
                Toast.makeText(this, getString(R.string.rescue_vpn_consent_unavailable), Toast.LENGTH_SHORT).show()
            }
        } else {
            DastyabVpnService.start(this)
            Toast.makeText(this, getString(R.string.rescue_vpn_activated), Toast.LENGTH_SHORT).show()
            appendLog("OK: DastYab VPN is now active.\n")
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN_BLACKOUT && resultCode == RESULT_OK) {
            DastyabVpnService.start(this)
            Toast.makeText(this, getString(R.string.rescue_vpn_activated), Toast.LENGTH_SHORT).show()
            appendLog("OK: DastYab VPN is now active.\n")
        } else if (requestCode == REQ_OPEN_CONFIG_FILE && resultCode == RESULT_OK) {
            val uri = data?.data ?: return
            val (entry, extracted) = ConfigFileHarvester.importLocalUri(this, uri)
            if (entry != null) {
                if (extracted.isNotEmpty()) {
                    val merged = UniversalConfig.mergeBalanced(extracted + TunnelConfig.loadHarvestedConfigs(this), 4096)
                    TunnelConfig.saveHarvestedConfigs(this, merged)
                }
                refreshHarvestSummary()
                Toast.makeText(this, getString(R.string.rescue_vault_import_ok, entry.fileName, extracted.size), Toast.LENGTH_LONG).show()
                showVaultFileActionsDialog(entry)
            } else {
                Toast.makeText(this, getString(R.string.rescue_vault_import_fail), Toast.LENGTH_SHORT).show()
            }
        }
    }

    private fun runEdgeIpScout() {
        if (!busy.compareAndSet(false, true)) return
        setLoading(true)
        clearLog("Scouting clean Cloudflare/CDN IPv4 edge ranges (port 443)…\n")

        thread(isDaemon = true, name = "dastyab-ip-scout") {
            val results = CleanEndpointScout.scoutCleanEdgeIps()
            UiSafety.safePostUi(this, handler) {
                setLoading(false)
                busy.set(false)
                if (results.isEmpty()) {
                    appendLog("No clean edge IPs responded within 1.8s.\nTip: Try Clean DNS Scout or Emergency DNS Blackout VPN.\n")
                    return@safePostUi
                }
                appendLog("Found ${results.size} reachable Clean Edge IPs:\n")
                results.take(10).forEach { r ->
                    appendLog("  • ${r.address}  (${r.latencyMs} ms)  ${r.label}\n")
                }
                showApplyScoutedIpDialog(results.take(10))
            }
        }
    }

    private fun showApplyScoutedIpDialog(results: List<CleanEndpointScout.EndpointResult>) {
        val items = results.map { "${it.address}  ·  ${it.latencyMs} ms  (${it.label})" }.toTypedArray()
        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(getString(R.string.rescue_clean_ips_title))
                .setItems(items) { _, which ->
                    val chosenIp = results[which].address
                    val current = TunnelConfig.load(this).vlessUri
                    val patched = if (current.isNotBlank()) {
                        CleanEndpointScout.patchVlessWithCleanIp(current, chosenIp)
                    } else null
                    if (patched != null) {
                        TunnelConfig.saveVlessUri(this, patched)
                        Toast.makeText(this, getString(R.string.rescue_patched_vless_toast, chosenIp), Toast.LENGTH_SHORT).show()
                        appendLog("Patched VLESS endpoint with Clean IP $chosenIp.\n")
                        if (DastyabVpnService.isConnected()) DastyabVpnService.start(this)
                    } else {
                        if (UiSafety.copyTextSafely(this, "Clean Edge IP", chosenIp)) {
                            Toast.makeText(this, getString(R.string.rescue_copied_cleanip_toast, chosenIp), Toast.LENGTH_SHORT).show()
                        }
                        appendLog("Copied Clean IP $chosenIp to clipboard (import a vless:// link to auto-patch).\n")
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
        )
    }

    private fun runCleanDnsScout() {
        if (!busy.compareAndSet(false, true)) return
        setLoading(true)
        clearLog("Scouting unpoisoned Clean UDP DNS & DoH resolvers…\n")

        thread(isDaemon = true, name = "dastyab-dns-scout") {
            val results = CleanEndpointScout.scoutCleanDnsAndDoh()
            UiSafety.safePostUi(this, handler) {
                setLoading(false)
                busy.set(false)
                if (results.isEmpty()) {
                    appendLog("No external DNS or DoH resolvers responded.\nTip: Try an installed fallback VPN (Tor/Orbot, Lantern, SlipNet, WhiteVPN).\n")
                    return@safePostUi
                }
                appendLog("Found ${results.size} reachable DNS / DoH resolvers:\n")
                results.take(10).forEach { r ->
                    appendLog("  • ${r.label}: ${r.address} (${r.latencyMs} ms)\n")
                }
                val items = results.take(10).map { "${it.label} · ${it.latencyMs} ms" }.toTypedArray()
                UiSafety.safeShowDialog(
                    this,
                    AlertDialog.Builder(this)
                        .setTitle(getString(R.string.rescue_clean_dns_title))
                        .setItems(items) { _, which ->
                            val picked = results[which]
                            if (picked.kind == CleanEndpointScout.Kind.DOH) {
                                TunnelConfig.saveDohAndDns(this, picked.address, null)
                                Toast.makeText(this, getString(R.string.rescue_set_doh_toast, picked.label), Toast.LENGTH_SHORT).show()
                                appendLog("Applied DoH resolver → ${picked.address}\n")
                            } else {
                                TunnelConfig.saveDohAndDns(this, null, picked.address)
                                Toast.makeText(this, getString(R.string.rescue_set_dns_toast, picked.address), Toast.LENGTH_SHORT).show()
                                appendLog("Applied Primary Clean DNS → ${picked.address}\n")
                            }
                            if (DastyabVpnService.isConnected()) DastyabVpnService.start(this)
                        }
                        .setNegativeButton(android.R.string.cancel, null)
                )
            }
        }
    }

    private fun runTroubleshooter() {
        if (!busy.compareAndSet(false, true)) return
        setLoading(true)
        clearLog("Running 7-layer connectivity & censorship diagnostics…\n")

        thread(isDaemon = true, name = "dastyab-troubleshoot") {
            val report = ConnectivityTroubleshooter.runLiveDiagnostics(this) { step ->
                appendLog("  • $step\n")
            }
            UiSafety.safePostUi(this, handler) {
                setLoading(false)
                busy.set(false)
                tvDiagnosisHeadline.text = "${report.headline}\n${report.summary}"
                val s = report.snapshot
                fun fmt(ms: Long) = if (ms >= 0) "${ms}ms" else "BLOCKED"
                appendLog(
                    "\n=== DIAGNOSIS: ${report.headline} ===\n" +
                        "Clean UDP DNS : ${fmt(s.cleanDnsMs)}\n" +
                        "DoH (HTTPS)   : ${fmt(s.dohMs)}\n" +
                        "GitHub Raw    : ${fmt(s.githubDirectMs)}\n" +
                        "GitHub Mirror : ${fmt(s.githubMirrorMs)}\n" +
                        "Telegram Web  : ${fmt(s.telegramMs)}\n" +
                        "AI Studio     : ${fmt(s.aiStudioMs)}\n" +
                        "Google Flow   : ${fmt(s.flowMs)}\n" +
                        "Active VPN    : ${s.vpnActive}\n" +
                        "Fallback Apps : ${s.installedFallbackCount}\n\n" +
                        "${report.summary}\n"
                )
                showRescuePlanDialog(report)
            }
        }
    }

    private fun showRescuePlanDialog(report: ConnectivityTroubleshooter.DiagnosticReport) {
        val labels = report.rescueSteps.mapIndexed { i, step -> "${i + 1}. ${step.title} — ${step.detail}" }.toTypedArray()
        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(report.headline)
                .setItems(labels) { _, which ->
                    when (report.rescueSteps[which].actionId) {
                        ConnectivityTroubleshooter.RescueActionId.CONNECT_SMART_VPN -> {
                            TunnelConfig.saveMode(this, TunnelConfig.Mode.SMART)
                            requestStartVpnNow()
                        }
                        ConnectivityTroubleshooter.RescueActionId.ENABLE_DNS_BLACKOUT_VPN -> activateDnsBlackoutVpn()
                        ConnectivityTroubleshooter.RescueActionId.HARVEST_CONFIGS -> runSmartHarvest()
                        ConnectivityTroubleshooter.RescueActionId.RUN_IP_SCOUT -> runEdgeIpScout()
                        ConnectivityTroubleshooter.RescueActionId.SET_BOOTSTRAP_CONFIG -> showBootstrapConfigDialog()
                        ConnectivityTroubleshooter.RescueActionId.LAUNCH_FALLBACK_VPN -> {
                            val installed = ConfigHarvester.detectFallbackTools(this).firstOrNull { it.isInstalled }
                            val launch = installed?.installedPackage?.let { packageManager.getLaunchIntentForPackage(it) }
                            if (launch == null || !UiSafety.safeStartActivity(this, launch)) {
                                Toast.makeText(this, getString(R.string.rescue_install_fallback_toast), Toast.LENGTH_SHORT).show()
                            }
                        }
                        ConnectivityTroubleshooter.RescueActionId.OPEN_TUNNEL_SETTINGS -> {
                            UiSafety.safeStartActivity(this, Intent(this, TunnelSettingsActivity::class.java))
                        }
                    }
                }
                .setNegativeButton(android.R.string.ok, null)
        )
    }

    private fun openExternalUrl(url: String) {
        if (!UiSafety.safeStartActivity(this, Intent(Intent.ACTION_VIEW, Uri.parse(url)))) {
            Toast.makeText(this, "Open in browser: $url", Toast.LENGTH_LONG).show()
        }
    }

    private fun setLoading(loading: Boolean) {
        progress.visibility = if (loading) View.VISIBLE else View.GONE
    }

    private fun clearLog(initial: String) {
        UiSafety.safePostUi(this, handler) { tvRescueLog.text = initial }
    }

    private fun appendLog(text: String) {
        UiSafety.safePostUi(this, handler) { tvRescueLog.append(text) }
    }

    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        super.onDestroy()
    }
}
