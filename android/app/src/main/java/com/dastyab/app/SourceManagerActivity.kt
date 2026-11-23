package com.dastyab.app

import android.app.AlertDialog
import android.content.ClipboardManager
import android.content.Context
import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import android.os.Handler
import android.os.Looper
import android.view.View
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.EditText
import android.widget.LinearLayout
import android.widget.ProgressBar
import android.widget.Spinner
import android.widget.Switch
import android.widget.TextView
import android.widget.Toast
import java.text.SimpleDateFormat
import java.util.Date
import java.util.Locale
import java.util.concurrent.atomic.AtomicBoolean
import kotlin.concurrent.thread

/**
 * SourceManagerActivity — Full unified Source Manager, Multi-Mirror Harvester,
 * TCP/TLS Latency Ranker, and One-Tap Client Exporter (Copy / Base64 Sub / QR /
 * v2rayNG / Hiddify / NekoBox).
 */
class SourceManagerActivity : DastyabActivity() {

    companion object {
        private const val REQ_VPN_PREPARE = 6201
    }

    private val protocolOptions = listOf(
        "All Protocols" to "all",
        "VLESS" to "vless",
        "VMess" to "vmess",
        "Trojan" to "trojan",
        "Shadowsocks (SS)" to "ss",
        "ShadowsocksR (SSR)" to "ssr",
        "Hysteria2 (hy2)" to "hysteria2",
        "Hysteria v1" to "hysteria",
        "TUIC" to "tuic",
        "WireGuard / WARP" to "wireguard",
        "SOCKS5 / SOCKS" to "socks5",
        "HTTP / HTTPS Proxy" to "http/https",
        "Naive+HTTPS" to "naive+https",
        "Juicity" to "juicity",
        "AnyTLS" to "anytls",
        "MTProto" to "mtproto"
    )

    private lateinit var progress: ProgressBar
    private lateinit var spinnerProtocol: Spinner
    private lateinit var tvHarvestStatus: TextView
    private lateinit var tvHarvestLog: TextView
    private lateinit var tvSourcesSummary: TextView
    private lateinit var resultsListContainer: LinearLayout
    private lateinit var sourcesListContainer: LinearLayout

    private lateinit var btnFilterAll: Button
    private lateinit var btnFilterGithub: Button
    private lateinit var btnFilterSub: Button
    private lateinit var btnFilterTgChan: Button
    private lateinit var btnFilterTgPost: Button

    private var activeTypeFilter: HarvestSourceStore.SourceType? = null
    private var workingConfigs: List<String> = emptyList()
    private var rankedResults: List<HarvestSourceStore.ConfigProbeResult> = emptyList()

    private val handler = Handler(Looper.getMainLooper())
    private val busy = AtomicBoolean(false)
    private val dateFmt = SimpleDateFormat("MM-dd HH:mm", Locale.US)

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_source_manager)

        progress = findViewById(R.id.sourceMgrProgress)
        spinnerProtocol = findViewById(R.id.spinnerProtocolFilter)
        tvHarvestStatus = findViewById(R.id.tvHarvestStatus)
        tvHarvestLog = findViewById(R.id.tvHarvestLog)
        tvSourcesSummary = findViewById(R.id.tvSourcesSummary)
        resultsListContainer = findViewById(R.id.resultsListContainer)
        sourcesListContainer = findViewById(R.id.sourcesListContainer)

        btnFilterAll = findViewById(R.id.btnFilterAll)
        btnFilterGithub = findViewById(R.id.btnFilterGithub)
        btnFilterSub = findViewById(R.id.btnFilterSub)
        btnFilterTgChan = findViewById(R.id.btnFilterTgChan)
        btnFilterTgPost = findViewById(R.id.btnFilterTgPost)

        spinnerProtocol.adapter = ArrayAdapter(
            this,
            android.R.layout.simple_spinner_item,
            protocolOptions.map { it.first }
        ).apply {
            setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        }

        workingConfigs = TunnelConfig.loadHarvestedConfigs(this)

        findViewById<Button>(R.id.btnRunUnifiedHarvest).setOnClickListener { runUnifiedHarvest() }
        findViewById<Button>(R.id.btnTestLatency).setOnClickListener { runLatencyTest() }

        findViewById<Button>(R.id.btnExportCopyAll).setOnClickListener { exportCopyAll() }
        findViewById<Button>(R.id.btnExportSubB64).setOnClickListener { exportBase64Sub() }
        findViewById<Button>(R.id.btnExportQr).setOnClickListener { exportQr() }
        findViewById<Button>(R.id.btnShareV2rayNg).setOnClickListener {
            shareToClient(ConfigHarvester.CLIENT_PACKAGE_V2RAYNG, "v2rayNG")
        }
        findViewById<Button>(R.id.btnShareHiddify).setOnClickListener {
            shareToClient(ConfigHarvester.CLIENT_PACKAGE_HIDDIFY, "Hiddify")
        }
        findViewById<Button>(R.id.btnShareNekoBox).setOnClickListener {
            shareToClient(ConfigHarvester.CLIENT_PACKAGE_NEKOBOX, "NekoBox")
        }

        btnFilterAll.setOnClickListener { setTypeFilter(null) }
        btnFilterGithub.setOnClickListener { setTypeFilter(HarvestSourceStore.SourceType.GITHUB_RAW) }
        btnFilterSub.setOnClickListener { setTypeFilter(HarvestSourceStore.SourceType.SUBSCRIPTION_URL) }
        btnFilterTgChan.setOnClickListener { setTypeFilter(HarvestSourceStore.SourceType.TELEGRAM_CHANNEL) }
        btnFilterTgPost.setOnClickListener { setTypeFilter(HarvestSourceStore.SourceType.TELEGRAM_POST) }

        findViewById<Button>(R.id.btnAddSource).setOnClickListener { showAddOrEditSourceDialog(null) }
        findViewById<Button>(R.id.btnBulkPaste).setOnClickListener { showBulkPasteDialog() }
        findViewById<Button>(R.id.btnImportSources).setOnClickListener { showImportSourcesDialog() }
        findViewById<Button>(R.id.btnExportSources).setOnClickListener { showExportSourcesDialog() }
        findViewById<Button>(R.id.btnResetSourcesDefaults).setOnClickListener { confirmResetDefaults() }
        findViewById<Button>(R.id.btnSourceMgrBack).setOnClickListener { finish() }

        refreshSourcesList()
        refreshResultsList()
        updateIdleStatus()
    }

    private fun selectedProtocolFilter(): String {
        val idx = spinnerProtocol.selectedItemPosition.coerceIn(0, protocolOptions.lastIndex)
        return protocolOptions[idx].second
    }

    private fun currentFilteredConfigs(): List<String> {
        return ConfigHarvester.filterByProtocol(workingConfigs, selectedProtocolFilter())
    }

    private fun updateIdleStatus() {
        val all = HarvestSourceStore.getAllSources(this)
        val enabled = all.count { it.enabled }
        val filtered = currentFilteredConfigs()
        tvHarvestStatus.text = getString(R.string.source_mgr_status_idle, filtered.size, enabled, all.size)
    }

    private fun setTypeFilter(type: HarvestSourceStore.SourceType?) {
        activeTypeFilter = type
        refreshSourcesList()
    }

    private fun runUnifiedHarvest() {
        if (!busy.compareAndSet(false, true)) return
        val filter = selectedProtocolFilter()
        progress.visibility = View.VISIBLE
        tvHarvestStatus.text = getString(R.string.source_mgr_status_harvesting)
        tvHarvestLog.text = ""
        rankedResults = emptyList()

        thread(isDaemon = true, name = "dastyab-unified-harvest") {
            val res = ConfigHarvester.harvestFromUnifiedSources(
                context = this,
                protocolFilter = filter,
                telegramPages = 3
            ) { line ->
                UiSafety.safePostUi(this, handler) {
                    val existing = tvHarvestLog.text?.toString().orEmpty()
                    val lines = (existing.lines() + line).filter { it.isNotEmpty() }.takeLast(14)
                    tvHarvestLog.text = lines.joinToString("\n")
                }
            }
            UiSafety.safePostUi(this, handler) {
                progress.visibility = View.GONE
                busy.set(false)
                workingConfigs = res.configs
                tvHarvestStatus.text = getString(
                    R.string.source_mgr_status_harvest_done,
                    res.configs.size,
                    res.sourcesSucceeded,
                    res.sourcesAttempted
                )
                refreshSourcesList()
                refreshResultsList()
            }
        }
    }

    private fun runLatencyTest() {
        val filtered = currentFilteredConfigs()
        if (filtered.isEmpty()) {
            Toast.makeText(this, getString(R.string.source_mgr_no_configs), Toast.LENGTH_SHORT).show()
            return
        }
        if (!busy.compareAndSet(false, true)) return
        val testLimit = filtered.size.coerceAtMost(50)
        progress.visibility = View.VISIBLE
        tvHarvestStatus.text = getString(R.string.source_mgr_status_testing, testLimit)

        thread(isDaemon = true, name = "dastyab-latency-rank") {
            val ranked = ConfigHarvester.testAndRankConfigs(
                configs = filtered,
                maxToTest = testLimit,
                timeoutMs = 2000,
                keepOnlyReachable = true
            )
            val reachableUris = ranked.map { it.uri }
            if (reachableUris.isNotEmpty()) {
                TunnelConfig.saveHarvestedConfigs(this, reachableUris)
            }
            UiSafety.safePostUi(this, handler) {
                progress.visibility = View.GONE
                busy.set(false)
                rankedResults = ranked
                if (reachableUris.isNotEmpty()) {
                    workingConfigs = reachableUris
                }
                tvHarvestStatus.text = getString(R.string.source_mgr_status_tested, ranked.size)
                refreshResultsList()
            }
        }
    }

    private fun refreshResultsList() {
        resultsListContainer.removeAllViews()
        val density = resources.displayMetrics.density

        if (rankedResults.isNotEmpty()) {
            rankedResults.take(40).forEachIndexed { idx, res ->
                val tlsBadge = if (res.tlsVerified) " · TLS✓" else ""
                val btn = Button(this, null, 0, R.style.DastyabButton).apply {
                    text = "#${idx + 1} [${res.protocol.uppercase()}] ${res.host}:${res.port} · ${res.latencyMs} ms$tlsBadge"
                    textSize = 12f
                    setOnClickListener { showConfigActionDialog(res.uri) }
                }
                val lp = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply { topMargin = (6 * density).toInt() }
                resultsListContainer.addView(btn, lp)
            }
            return
        }

        val configs = currentFilteredConfigs()
        configs.take(20).forEachIndexed { idx, uri ->
            val ep = UniversalConfig.parse(uri)
            val label = ep?.let { "#${idx + 1} ${it.summary()}" } ?: "#${idx + 1} ${uri.take(64)}"
            val btn = Button(this, null, 0, R.style.DastyabButton).apply {
                text = label
                textSize = 12f
                setOnClickListener { showConfigActionDialog(uri) }
            }
            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { topMargin = (6 * density).toInt() }
            resultsListContainer.addView(btn, lp)
        }
    }

    private fun showConfigActionDialog(uri: String) {
        val ep = UniversalConfig.parse(uri)
        val proto = (ep?.protocol ?: UniversalConfig.protocolOf(uri)).uppercase()
        val options = arrayOf(
            getString(R.string.rescue_action_apply_vpn),
            getString(R.string.rescue_action_copy_uri),
            getString(R.string.layers_action_qr),
            getString(R.string.source_mgr_btn_share_v2rayng),
            getString(R.string.source_mgr_btn_share_hiddify),
            getString(R.string.source_mgr_btn_share_nekobox)
        )
        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(ep?.summary() ?: proto)
                .setItems(options) { _, which ->
                    when (which) {
                        0 -> applyAndStartVpn(uri)
                        1 -> {
                            UiSafety.copyTextSafely(this, "DastYab $proto", uri)
                            Toast.makeText(this, getString(R.string.copied_to_clipboard), Toast.LENGTH_SHORT).show()
                        }
                        2 -> QrShareDialog.show(this, proto, uri)
                        3 -> ConfigHarvester.shareToExternalClient(this, ConfigHarvester.CLIENT_PACKAGE_V2RAYNG, "v2rayNG", listOf(uri))
                        4 -> ConfigHarvester.shareToExternalClient(this, ConfigHarvester.CLIENT_PACKAGE_HIDDIFY, "Hiddify", listOf(uri))
                        5 -> ConfigHarvester.shareToExternalClient(this, ConfigHarvester.CLIENT_PACKAGE_NEKOBOX, "NekoBox", listOf(uri))
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
        )
    }

    private fun applyAndStartVpn(uri: String) {
        TunnelConfig.saveActiveConfigUri(this, uri)
        TunnelConfig.saveMode(this, TunnelConfig.Mode.SMART)
        val prep = try {
            VpnService.prepare(this)
        } catch (_: Exception) {
            null
        }
        if (prep != null) {
            @Suppress("DEPRECATION")
            startActivityForResult(prep, REQ_VPN_PREPARE)
        } else {
            DastyabVpnService.start(this)
            Toast.makeText(this, getString(R.string.layers_vpn_connected_toast), Toast.LENGTH_SHORT).show()
        }
    }

    @Deprecated("Required for VpnService.prepare result")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN_PREPARE && resultCode == RESULT_OK) {
            DastyabVpnService.start(this)
            Toast.makeText(this, getString(R.string.layers_vpn_connected_toast), Toast.LENGTH_SHORT).show()
        }
    }

    private fun exportCopyAll() {
        val configs = currentFilteredConfigs()
        if (configs.isEmpty()) {
            Toast.makeText(this, getString(R.string.source_mgr_no_configs), Toast.LENGTH_SHORT).show()
            return
        }
        val text = ConfigHarvester.toPlainTextExport(configs)
        if (UiSafety.copyTextSafely(this, "DastYab Configs", text)) {
            Toast.makeText(this, getString(R.string.source_mgr_exported_count, configs.size), Toast.LENGTH_SHORT).show()
        }
    }

    private fun exportBase64Sub() {
        val configs = currentFilteredConfigs()
        if (configs.isEmpty()) {
            Toast.makeText(this, getString(R.string.source_mgr_no_configs), Toast.LENGTH_SHORT).show()
            return
        }
        val b64 = ConfigHarvester.toBase64Subscription(configs)
        if (UiSafety.copyTextSafely(this, "DastYab Subscription", b64)) {
            Toast.makeText(this, getString(R.string.source_mgr_exported_sub, configs.size), Toast.LENGTH_SHORT).show()
        }
    }

    private fun exportQr() {
        val configs = currentFilteredConfigs()
        if (configs.isEmpty()) {
            Toast.makeText(this, getString(R.string.source_mgr_no_configs), Toast.LENGTH_SHORT).show()
            return
        }
        val sb = StringBuilder()
        for (u in configs) {
            if (sb.length + u.length + 1 > 1600) break
            if (sb.isNotEmpty()) sb.append('\n')
            sb.append(u)
        }
        val payload = sb.toString().ifEmpty { configs.first() }
        QrShareDialog.show(this, getString(R.string.source_mgr_qr_title), payload)
    }

    private fun shareToClient(packageName: String, label: String) {
        val configs = currentFilteredConfigs()
        if (configs.isEmpty()) {
            Toast.makeText(this, getString(R.string.source_mgr_no_configs), Toast.LENGTH_SHORT).show()
            return
        }
        ConfigHarvester.shareToExternalClient(this, packageName, label, configs)
    }

    private fun refreshSourcesList() {
        sourcesListContainer.removeAllViews()
        val all = HarvestSourceStore.getAllSources(this)
        val filtered = if (activeTypeFilter == null) all else all.filter { it.type == activeTypeFilter }
        val enabledCount = all.count { it.enabled }
        tvSourcesSummary.text = getString(R.string.source_mgr_summary_fmt, filtered.size, enabledCount, all.size)

        val density = resources.displayMetrics.density
        val pad = (10 * density).toInt()
        val textPrimary = ThemeManager.resolveColor(this, R.attr.dastyabTextPrimary, R.color.colorTextPrimary)
        val textSecondary = ThemeManager.resolveColor(this, R.attr.dastyabTextSecondary, R.color.colorTextSecondary)
        val accentColor = ThemeManager.resolveColor(this, R.attr.dastyabAccent, R.color.colorAccent)

        for (src in filtered) {
            val card = LinearLayout(this).apply {
                orientation = LinearLayout.VERTICAL
                setBackgroundResource(R.drawable.card_background)
                setPadding(pad, pad, pad, pad)
            }

            val topRow = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
            }
            val titleView = TextView(this).apply {
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                text = "[${src.type.displayLabel}] ${src.name}"
                textSize = 13f
                setTextColor(textPrimary)
                setTypeface(typeface, android.graphics.Typeface.BOLD)
            }
            @Suppress("UseSwitchCompatOrMaterialCode")
            val toggle = Switch(this).apply {
                isChecked = src.enabled
                setOnCheckedChangeListener { _, checked ->
                    HarvestSourceStore.setSourceEnabled(this@SourceManagerActivity, src.id, checked)
                    updateIdleStatus()
                }
            }
            topRow.addView(titleView)
            topRow.addView(toggle)
            card.addView(topRow)

            val valueView = TextView(this).apply {
                text = src.value
                textSize = 11f
                setTextColor(accentColor)
                setPadding(0, (2 * density).toInt(), 0, (2 * density).toInt())
            }
            card.addView(valueView)

            val lastStr = if (src.lastFetchTimeMs > 0L) {
                dateFmt.format(Date(src.lastFetchTimeMs))
            } else {
                getString(R.string.source_mgr_never_fetched)
            }
            val statsView = TextView(this).apply {
                text = getString(
                    R.string.source_mgr_stats_fmt,
                    src.configsFound,
                    src.successRate,
                    src.successCount,
                    src.attemptCount,
                    lastStr
                )
                textSize = 11f
                setTextColor(textSecondary)
                setPadding(0, 0, 0, (6 * density).toInt())
            }
            card.addView(statsView)

            val actionRow = LinearLayout(this).apply {
                orientation = LinearLayout.HORIZONTAL
            }
            val btnEdit = Button(this, null, 0, R.style.DastyabButton).apply {
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                text = getString(R.string.source_mgr_btn_edit)
                textSize = 12f
                setOnClickListener { showAddOrEditSourceDialog(src) }
            }
            val spacer = View(this).apply {
                layoutParams = LinearLayout.LayoutParams((8 * density).toInt(), 0)
            }
            val btnRemove = Button(this, null, 0, R.style.DastyabButton).apply {
                layoutParams = LinearLayout.LayoutParams(0, LinearLayout.LayoutParams.WRAP_CONTENT, 1f)
                text = getString(R.string.source_mgr_btn_remove)
                textSize = 12f
                setOnClickListener {
                    HarvestSourceStore.removeSource(this@SourceManagerActivity, src.id)
                    Toast.makeText(this@SourceManagerActivity, getString(R.string.source_mgr_removed_toast), Toast.LENGTH_SHORT).show()
                    refreshSourcesList()
                    updateIdleStatus()
                }
            }
            actionRow.addView(btnEdit)
            actionRow.addView(spacer)
            actionRow.addView(btnRemove)
            card.addView(actionRow)

            val lp = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply { bottomMargin = (8 * density).toInt() }
            sourcesListContainer.addView(card, lp)
        }
    }

    private fun showAddOrEditSourceDialog(existing: HarvestSourceStore.HarvestSource?) {
        val density = resources.displayMetrics.density
        val pad = (16 * density).toInt()
        val types = HarvestSourceStore.SourceType.values()
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }
        val spinnerType = Spinner(this).apply {
            adapter = ArrayAdapter(
                this@SourceManagerActivity,
                android.R.layout.simple_spinner_item,
                types.map { it.displayLabel }
            ).apply {
                setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
            }
            if (existing != null) {
                setSelection(types.indexOf(existing.type).coerceAtLeast(0))
            }
        }
        val etName = EditText(this).apply {
            hint = getString(R.string.source_mgr_hint_name)
            setText(existing?.name.orEmpty())
        }
        val etValue = EditText(this).apply {
            hint = getString(R.string.source_mgr_hint_value)
            setText(existing?.value.orEmpty())
        }
        val cbEnabled = CheckBox(this).apply {
            text = getString(R.string.source_mgr_enabled_label)
            isChecked = existing?.enabled ?: true
        }
        container.addView(spinnerType)
        container.addView(etName)
        container.addView(etValue)
        container.addView(cbEnabled)

        val titleRes = if (existing == null) R.string.source_mgr_add_title else R.string.source_mgr_edit_title
        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(getString(titleRes))
                .setView(container)
                .setPositiveButton(android.R.string.ok) { _, _ ->
                    val chosenType = types[spinnerType.selectedItemPosition.coerceIn(0, types.lastIndex)]
                    val name = etName.text.toString().trim()
                    val value = etValue.text.toString().trim()
                    val ok = if (existing == null) {
                        val added = HarvestSourceStore.addSource(this, name, chosenType, value)
                        if (added != null && !cbEnabled.isChecked) {
                            HarvestSourceStore.setSourceEnabled(this, added.id, false)
                        }
                        added != null
                    } else {
                        HarvestSourceStore.updateSource(this, existing.id, name, chosenType, value, cbEnabled.isChecked)
                    }
                    if (ok) {
                        Toast.makeText(this, getString(R.string.source_mgr_saved_toast), Toast.LENGTH_SHORT).show()
                        refreshSourcesList()
                        updateIdleStatus()
                    } else {
                        Toast.makeText(this, getString(R.string.source_mgr_invalid_source), Toast.LENGTH_LONG).show()
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
        )
    }

    private fun showBulkPasteDialog() {
        val density = resources.displayMetrics.density
        val pad = (16 * density).toInt()
        val et = EditText(this).apply {
            hint = getString(R.string.source_mgr_bulk_hint)
            minLines = 5
            setPadding(pad, pad, pad, pad)
        }
        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(getString(R.string.source_mgr_bulk_title))
                .setView(et)
                .setPositiveButton(R.string.layers_btn_do_add) { _, _ ->
                    val added = HarvestSourceStore.bulkAddSources(this, et.text.toString())
                    if (added > 0) {
                        Toast.makeText(this, getString(R.string.source_mgr_bulk_added, added), Toast.LENGTH_SHORT).show()
                        refreshSourcesList()
                        updateIdleStatus()
                    } else {
                        Toast.makeText(this, getString(R.string.source_mgr_invalid_source), Toast.LENGTH_LONG).show()
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
        )
    }

    private fun showImportSourcesDialog() {
        val density = resources.displayMetrics.density
        val pad = (16 * density).toInt()
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }
        val et = EditText(this).apply {
            hint = getString(R.string.source_mgr_import_hint)
            minLines = 5
        }
        val cbReplace = CheckBox(this).apply {
            text = getString(R.string.source_mgr_import_replace)
            isChecked = false
        }
        val cm = getSystemService(Context.CLIPBOARD_SERVICE) as? ClipboardManager
        val clipText = cm?.primaryClip?.getItemAt(0)?.text?.toString().orEmpty()
        if (clipText.isNotBlank() && (clipText.trim().startsWith("[") || clipText.contains("http") || clipText.contains("t.me"))) {
            et.setText(clipText)
        }
        container.addView(et)
        container.addView(cbReplace)

        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(getString(R.string.source_mgr_import_title))
                .setView(container)
                .setPositiveButton(R.string.layers_btn_do_import) { _, _ ->
                    val count = HarvestSourceStore.importSources(this, et.text.toString(), cbReplace.isChecked)
                    if (count > 0) {
                        Toast.makeText(this, getString(R.string.source_mgr_imported_toast, count), Toast.LENGTH_SHORT).show()
                        refreshSourcesList()
                        updateIdleStatus()
                    } else {
                        Toast.makeText(this, getString(R.string.source_mgr_invalid_source), Toast.LENGTH_LONG).show()
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
        )
    }

    private fun showExportSourcesDialog() {
        val all = HarvestSourceStore.getAllSources(this)
        val json = HarvestSourceStore.serializeSourcesJson(all)
        val text = HarvestSourceStore.exportSourcesText(all)
        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(getString(R.string.source_mgr_export_title))
                .setMessage(text.take(1200))
                .setPositiveButton(R.string.source_mgr_export_json) { _, _ ->
                    if (UiSafety.copyTextSafely(this, "DastYab Sources JSON", json)) {
                        Toast.makeText(this, getString(R.string.copied_to_clipboard), Toast.LENGTH_SHORT).show()
                    }
                }
                .setNeutralButton(R.string.source_mgr_export_text) { _, _ ->
                    if (UiSafety.copyTextSafely(this, "DastYab Sources Text", text)) {
                        Toast.makeText(this, getString(R.string.copied_to_clipboard), Toast.LENGTH_SHORT).show()
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
        )
    }

    private fun confirmResetDefaults() {
        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(getString(R.string.source_mgr_reset_confirm_title))
                .setMessage(getString(R.string.source_mgr_reset_confirm_msg))
                .setPositiveButton(android.R.string.ok) { _, _ ->
                    HarvestSourceStore.resetToDefaults(this)
                    refreshSourcesList()
                    updateIdleStatus()
                    Toast.makeText(this, getString(R.string.layers_sources_reset_toast), Toast.LENGTH_SHORT).show()
                }
                .setNegativeButton(android.R.string.cancel, null)
        )
    }
}
