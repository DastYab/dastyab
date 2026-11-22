package com.dastyab.app

import android.app.AlertDialog
import android.content.Intent
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
import kotlin.concurrent.thread

/**
 * VpnLayersActivity — Visual Multi-Layer VPN Manager + Harvester GitHub URLs & Telegram Channels Editor.
 *
 * Allows the user to:
 *  • Add, edit, clone, delete, benchmark, and 1-tap activate custom VPN layers
 *  • Export / Import all VPN layers as portable JSON
 *  • Add (single or bulk), edit, and remove custom GitHub subscription URLs (auto-converts blob → raw)
 *  • Add (single or bulk) and remove custom Telegram channels (`@channel` or `t.me/s/channel`)
 *  • Benchmark the harvested config pool in parallel and promote the fastest working config into a VPN layer
 */
class VpnLayersActivity : DastyabActivity() {

    companion object {
        private const val REQ_VPN_LAYER_START = 6001
    }

    private lateinit var progress: ProgressBar
    private lateinit var layersListContainer: LinearLayout
    private lateinit var githubUrlsContainer: LinearLayout
    private lateinit var telegramChannelsContainer: LinearLayout
    private lateinit var tvGithubCount: TextView
    private lateinit var tvTelegramCount: TextView
    private lateinit var tvLayersLog: TextView

    private val handler = Handler(Looper.getMainLooper())

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_vpn_layers)

        progress = findViewById(R.id.layersProgress)
        layersListContainer = findViewById(R.id.layersListContainer)
        githubUrlsContainer = findViewById(R.id.githubUrlsContainer)
        telegramChannelsContainer = findViewById(R.id.telegramChannelsContainer)
        tvGithubCount = findViewById(R.id.tvGithubCount)
        tvTelegramCount = findViewById(R.id.tvTelegramCount)
        tvLayersLog = findViewById(R.id.tvLayersLog)

        findViewById<Button>(R.id.btnAddLayer).setOnClickListener { showLayerEditorDialog(null) }
        findViewById<Button>(R.id.btnAutoBestLayer).setOnClickListener { benchmarkAndSwitchBestLayer() }
        findViewById<Button>(R.id.btnAutoBuildShield).setOnClickListener { buildStrongMultiLayerShield() }
        findViewById<Button>(R.id.btnExportLayers).setOnClickListener { exportLayersToClipboard() }
        findViewById<Button>(R.id.btnImportLayers).setOnClickListener { showImportLayersDialog() }

        findViewById<Button>(R.id.btnAddGithubUrl).setOnClickListener { showAddGithubUrlDialog() }
        findViewById<Button>(R.id.btnAddTelegramChannel).setOnClickListener { showAddTelegramChannelDialog() }
        findViewById<Button>(R.id.btnBenchmarkPool).setOnClickListener { benchmarkHarvestedPool() }
        findViewById<Button>(R.id.btnResetSources).setOnClickListener {
            HarvestSourceStore.resetToDefaults(this)
            refreshSourcesUi()
            Toast.makeText(this, getString(R.string.layers_sources_reset_toast), Toast.LENGTH_SHORT).show()
        }
        findViewById<Button>(R.id.btnLayersBack).setOnClickListener { finish() }

        refreshAllUi()
    }

    private fun refreshAllUi() {
        refreshLayersUi()
        refreshSourcesUi()
    }

    private fun refreshLayersUi() {
        layersListContainer.removeAllViews()
        val layers = VpnLayerStore.loadAll(this)
        val activeId = VpnLayerStore.getActiveLayerId(this)
        val density = resources.displayMetrics.density

        for (layer in layers) {
            val isActive = layer.id == activeId
            val btn = Button(this, null, 0, if (isActive) R.style.DastyabButtonPrimary else R.style.DastyabButton).apply {
                val marker = if (isActive) getString(R.string.layers_active_prefix) else ""
                text = "$marker${layer.name}\n${layer.mode.localizedLabel(this@VpnLayersActivity)} · ${layer.dnsPrimary}"
                setOnClickListener { showLayerActionSheet(layer) }
            }
            val params = LinearLayout.LayoutParams(
                LinearLayout.LayoutParams.MATCH_PARENT,
                LinearLayout.LayoutParams.WRAP_CONTENT
            ).apply {
                bottomMargin = (8 * density).toInt()
            }
            DastyabMotion.attachPressSpring(btn)
            layersListContainer.addView(btn, params)
        }
    }

    private fun showLayerActionSheet(layer: VpnLayerStore.VpnLayer) {
        val options = arrayOf(
            getString(R.string.layers_action_activate),
            getString(R.string.layers_action_edit),
            getString(R.string.layers_action_qr),
            getString(R.string.layers_action_clone),
            getString(R.string.layers_action_delete)
        )
        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(layer.name)
                .setItems(options) { _, which ->
                    when (which) {
                        0 -> {
                            VpnLayerStore.activateLayer(this, layer, restartIfConnected = false)
                            refreshLayersUi()
                            startVpnWithConsent()
                        }
                        1 -> showLayerEditorDialog(layer)
                        2 -> {
                            val payload = layer.configUri.ifBlank { layer.dohUrl }
                            QrShareDialog.show(this, "QR · ${layer.name}", payload)
                        }
                        3 -> {
                            val copy = layer.copy(
                                id = java.util.UUID.randomUUID().toString().take(8),
                                name = "${layer.name} ${getString(R.string.layers_copy_suffix)}"
                            )
                            VpnLayerStore.addOrUpdate(this, copy)
                            refreshLayersUi()
                            Toast.makeText(this, getString(R.string.layers_cloned_toast), Toast.LENGTH_SHORT).show()
                        }
                        4 -> {
                            VpnLayerStore.delete(this, layer.id)
                            refreshLayersUi()
                            Toast.makeText(this, getString(R.string.layers_deleted_toast), Toast.LENGTH_SHORT).show()
                        }
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
        )
    }

    private fun showLayerEditorDialog(existing: VpnLayerStore.VpnLayer?) {
        val pad = (14 * resources.displayMetrics.density).toInt()
        val container = LinearLayout(this).apply {
            orientation = LinearLayout.VERTICAL
            setPadding(pad, pad, pad, pad)
        }
        val etName = EditText(this).apply {
            hint = getString(R.string.layers_hint_name)
            setText(existing?.name ?: "")
        }
        val modes = TunnelConfig.Mode.values()
        val spinnerMode = Spinner(this).apply {
            adapter = ArrayAdapter(
                this@VpnLayersActivity,
                android.R.layout.simple_spinner_item,
                modes.map { it.localizedLabel(this@VpnLayersActivity) }
            ).apply {
                setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
            }
            val idx = modes.indexOf(existing?.mode ?: TunnelConfig.Mode.SMART).coerceAtLeast(0)
            setSelection(idx)
        }
        val etUri = EditText(this).apply {
            hint = getString(R.string.layers_hint_uri)
            setText(existing?.configUri ?: "")
            setSingleLine(false)
            maxLines = 3
        }
        val etDns = EditText(this).apply {
            hint = getString(R.string.layers_hint_dns)
            setText(existing?.dnsPrimary ?: TunnelConfig.DEFAULT_DNS_PRIMARY)
        }
        val etDoh = EditText(this).apply {
            hint = getString(R.string.layers_hint_doh)
            setText(existing?.dohUrl ?: TunnelConfig.DEFAULT_DOH_URL)
        }

        container.addView(etName)
        container.addView(spinnerMode)
        container.addView(etUri)
        container.addView(etDns)
        container.addView(etDoh)

        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(if (existing == null) getString(R.string.layers_add_title) else getString(R.string.layers_edit_title))
                .setView(container)
                .setPositiveButton(getString(R.string.layers_save_activate)) { _, _ ->
                    val name = etName.text.toString().trim().ifEmpty { getString(R.string.layers_default_custom_name) }
                    val mode = modes[spinnerMode.selectedItemPosition.coerceIn(0, modes.lastIndex)]
                    val layer = (existing ?: VpnLayerStore.VpnLayer(name = name, mode = mode)).copy(
                        name = name,
                        mode = mode,
                        configUri = etUri.text.toString().trim(),
                        dnsPrimary = TunnelConfig.sanitizeDns(etDns.text.toString(), TunnelConfig.DEFAULT_DNS_PRIMARY),
                        dohUrl = TunnelConfig.sanitizeDohUrl(etDoh.text.toString())
                    )
                    VpnLayerStore.addOrUpdate(this, layer)
                    VpnLayerStore.activateLayer(this, layer, restartIfConnected = true)
                    refreshLayersUi()
                    tvLayersLog.text = getString(R.string.layers_saved_log, layer.name, layer.subtitle())
                    Toast.makeText(this, getString(R.string.layers_saved_toast), Toast.LENGTH_SHORT).show()
                }
                .setNegativeButton(android.R.string.cancel, null)
        )
    }

    private fun benchmarkAndSwitchBestLayer() {
        progress.visibility = View.VISIBLE
        tvLayersLog.text = getString(R.string.layers_bench_running)
        val layers = VpnLayerStore.loadAll(this)
        thread(isDaemon = true, name = "dastyab-layer-bench") {
            val results = VpnLayerStore.benchmarkLayers(layers)
            UiSafety.safePostUi(this, handler) {
                progress.visibility = View.GONE
                val sb = StringBuilder("=== VPN LAYER BENCHMARK ===\n")
                results.forEach { r ->
                    val status = if (r.reachable) "${r.latencyMs} ms" else "UNREACHABLE"
                    sb.append("• ${r.layer.name}: $status\n")
                }
                val best = results.firstOrNull { it.reachable }
                if (best != null) {
                    VpnLayerStore.activateLayer(this, best.layer, restartIfConnected = true)
                    refreshLayersUi()
                    sb.append("\n✓ Switched to fastest layer: ${best.layer.name} (${best.latencyMs} ms)")
                    Toast.makeText(this, getString(R.string.layers_switched_fastest_toast, best.layer.name, best.latencyMs.toInt()), Toast.LENGTH_SHORT).show()
                } else {
                    sb.append("\n✗ No layers responded — try DNS Blackout VPN or IP Scout.")
                }
                tvLayersLog.text = sb.toString()
            }
        }
    }

    private fun buildStrongMultiLayerShield() {
        progress.visibility = View.VISIBLE
        tvLayersLog.text = getString(R.string.layers_shield_building)
        thread(isDaemon = true, name = "dastyab-build-shield") {
            val stack = VpnLayerStore.buildHardenedResilienceStack(this)
            val bench = VpnLayerStore.benchmarkLayers(stack, timeoutMs = 1800)
            UiSafety.safePostUi(this, handler) {
                progress.visibility = View.GONE
                val best = bench.firstOrNull { it.reachable }
                if (best != null) {
                    VpnLayerStore.activateLayer(this, best.layer, restartIfConnected = true)
                }
                refreshLayersUi()
                val sb = StringBuilder("=== STRONG MULTI-LAYER SHIELD (${stack.size} LAYERS) ===\n")
                bench.forEach { r ->
                    val status = if (r.reachable) "${r.latencyMs}ms" else "STANDBY"
                    sb.append("• ${r.layer.name} [$status]\n  ${r.layer.subtitle()}\n")
                }
                tvLayersLog.text = sb.toString()
                Toast.makeText(this, getString(R.string.layers_shield_built_toast, stack.size), Toast.LENGTH_LONG).show()
            }
        }
    }

    private fun exportLayersToClipboard() {
        val json = VpnLayerStore.serializeLayers(VpnLayerStore.loadAll(this))
        if (UiSafety.copyTextSafely(this, "DastYab VPN Layers", json)) {
            Toast.makeText(this, getString(R.string.layers_exported_toast), Toast.LENGTH_SHORT).show()
        }
    }

    private fun showImportLayersDialog() {
        val input = EditText(this).apply {
            hint = getString(R.string.layers_import_hint)
            setSingleLine(false)
            maxLines = 5
        }
        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(getString(R.string.layers_import_title))
                .setView(input)
                .setPositiveButton(getString(R.string.layers_btn_do_import)) { _, _ ->
                    val imported = VpnLayerStore.deserializeLayers(input.text.toString())
                    if (imported.isEmpty()) {
                        Toast.makeText(this, getString(R.string.layers_import_invalid), Toast.LENGTH_SHORT).show()
                    } else {
                        VpnLayerStore.saveAll(this, imported)
                        refreshLayersUi()
                        Toast.makeText(this, getString(R.string.layers_imported_toast, imported.size), Toast.LENGTH_SHORT).show()
                    }
                }
                .setNegativeButton(android.R.string.cancel, null)
        )
    }

    private fun refreshSourcesUi() {
        val customUrls = HarvestSourceStore.getCustomGithubUrls(this)
        val customChannels = HarvestSourceStore.getCustomTelegramChannels(this)
        val density = resources.displayMetrics.density
        val textSecondary = ThemeManager.resolveColor(this, R.attr.dastyabTextSecondary, R.color.colorTextSecondary)

        tvGithubCount.text = getString(R.string.layers_github_count, customUrls.size, ConfigHarvester.DEFAULT_GITHUB_FEEDS.size)
        githubUrlsContainer.removeAllViews()
        if (customUrls.isEmpty()) {
            githubUrlsContainer.addView(TextView(this).apply {
                text = getString(R.string.layers_github_empty)
                textSize = 12f
                setTextColor(textSecondary)
            })
        } else {
            for (url in customUrls) {
                val btn = Button(this, null, 0, R.style.DastyabChip).apply {
                    text = "✕  ${url.removePrefix("https://").take(46)}"
                    setOnClickListener {
                        HarvestSourceStore.removeGithubUrl(this@VpnLayersActivity, url)
                        refreshSourcesUi()
                        Toast.makeText(this@VpnLayersActivity, getString(R.string.layers_removed_github_toast), Toast.LENGTH_SHORT).show()
                    }
                }
                val lp = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply { bottomMargin = (6 * density).toInt() }
                DastyabMotion.attachPressSpring(btn)
                githubUrlsContainer.addView(btn, lp)
            }
        }

        tvTelegramCount.text = getString(R.string.layers_telegram_count, customChannels.size, ConfigHarvester.DEFAULT_TELEGRAM_CHANNELS.size)
        telegramChannelsContainer.removeAllViews()
        if (customChannels.isEmpty()) {
            telegramChannelsContainer.addView(TextView(this).apply {
                text = getString(
                    R.string.layers_telegram_empty,
                    ConfigHarvester.DEFAULT_TELEGRAM_CHANNELS.joinToString { "@$it" }
                )
                textSize = 12f
                setTextColor(textSecondary)
            })
        } else {
            for (ch in customChannels) {
                val btn = Button(this, null, 0, R.style.DastyabChip).apply {
                    text = "✕  @$ch  (t.me/s/$ch)"
                    setOnClickListener {
                        HarvestSourceStore.removeTelegramChannel(this@VpnLayersActivity, ch)
                        refreshSourcesUi()
                        Toast.makeText(this@VpnLayersActivity, getString(R.string.layers_removed_channel_toast, ch), Toast.LENGTH_SHORT).show()
                    }
                }
                val lp = LinearLayout.LayoutParams(
                    LinearLayout.LayoutParams.MATCH_PARENT,
                    LinearLayout.LayoutParams.WRAP_CONTENT
                ).apply { bottomMargin = (6 * density).toInt() }
                DastyabMotion.attachPressSpring(btn)
                telegramChannelsContainer.addView(btn, lp)
            }
        }
    }

    private fun showAddGithubUrlDialog() {
        val input = EditText(this).apply {
            hint = getString(R.string.layers_add_github_hint)
            setSingleLine(false)
            maxLines = 5
        }
        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(getString(R.string.layers_add_github_title))
                .setView(input)
                .setPositiveButton(getString(R.string.layers_btn_do_add)) { _, _ ->
                    val added = HarvestSourceStore.addGithubUrls(this, input.text.toString())
                    refreshSourcesUi()
                    Toast.makeText(
                        this,
                        if (added > 0) getString(R.string.layers_added_github_toast, added) else getString(R.string.layers_invalid_github_toast),
                        Toast.LENGTH_SHORT
                    ).show()
                }
                .setNegativeButton(android.R.string.cancel, null)
        )
    }

    private fun showAddTelegramChannelDialog() {
        val input = EditText(this).apply {
            hint = getString(R.string.layers_add_telegram_hint)
            setSingleLine(false)
            maxLines = 5
        }
        UiSafety.safeShowDialog(
            this,
            AlertDialog.Builder(this)
                .setTitle(getString(R.string.layers_add_telegram_title))
                .setView(input)
                .setPositiveButton(getString(R.string.layers_btn_do_add)) { _, _ ->
                    val added = HarvestSourceStore.addTelegramChannels(this, input.text.toString())
                    refreshSourcesUi()
                    Toast.makeText(
                        this,
                        if (added > 0) getString(R.string.layers_added_telegram_toast, added) else getString(R.string.layers_invalid_telegram_toast),
                        Toast.LENGTH_SHORT
                    ).show()
                }
                .setNegativeButton(android.R.string.cancel, null)
        )
    }

    private fun benchmarkHarvestedPool() {
        val pool = TunnelConfig.loadHarvestedConfigs(this)
        if (pool.isEmpty()) {
            Toast.makeText(this, getString(R.string.layers_pool_empty_toast), Toast.LENGTH_SHORT).show()
            return
        }
        progress.visibility = View.VISIBLE
        tvLayersLog.text = getString(R.string.layers_pool_testing)
        thread(isDaemon = true, name = "dastyab-pool-bench") {
            val working = HarvestSourceStore.benchmarkHarvestedConfigs(pool, maxToTest = 60)
            UiSafety.safePostUi(this, handler) {
                progress.visibility = View.GONE
                if (working.isEmpty()) {
                    tvLayersLog.text = getString(R.string.layers_pool_none_responded)
                    return@safePostUi
                }
                val sb = StringBuilder("Found ${working.size} live configs (fastest first):\n")
                working.take(10).forEach { r ->
                    sb.append("• [${r.protocol.uppercase()}] ${r.host}:${r.port} (${r.latencyMs}ms)\n")
                }
                tvLayersLog.text = sb.toString()

                val items = working.take(10).map {
                    "[${it.protocol.uppercase()}] ${it.host}:${it.port} · ${it.latencyMs}ms"
                }.toTypedArray()
                UiSafety.safeShowDialog(
                    this,
                    AlertDialog.Builder(this)
                        .setTitle(getString(R.string.layers_promote_title))
                        .setItems(items) { _, which ->
                            val picked = working[which]
                            val newLayer = VpnLayerStore.VpnLayer(
                                name = "Fast ${picked.protocol.uppercase()} (${picked.host})",
                                mode = TunnelConfig.Mode.SMART,
                                configUri = picked.uri
                            )
                            VpnLayerStore.addOrUpdate(this, newLayer)
                            VpnLayerStore.activateLayer(this, newLayer, restartIfConnected = true)
                            refreshLayersUi()
                            Toast.makeText(this, getString(R.string.layers_promoted_toast, newLayer.name), Toast.LENGTH_SHORT).show()
                        }
                        .setNegativeButton(android.R.string.cancel, null)
                )
            }
        }
    }

    override fun onDestroy() {
        handler.removeCallbacksAndMessages(null)
        super.onDestroy()
    }

    private fun startVpnWithConsent() {
        val prep = VpnService.prepare(this)
        if (prep != null) {
            try {
                @Suppress("DEPRECATION")
                startActivityForResult(prep, REQ_VPN_LAYER_START)
            } catch (_: Exception) {
                Toast.makeText(this, getString(R.string.rescue_vpn_consent_unavailable), Toast.LENGTH_SHORT).show()
            }
        } else {
            DastyabVpnService.start(this)
            Toast.makeText(this, getString(R.string.layers_vpn_connected_toast), Toast.LENGTH_SHORT).show()
        }
    }

    @Deprecated("Deprecated in Java")
    override fun onActivityResult(requestCode: Int, resultCode: Int, data: Intent?) {
        @Suppress("DEPRECATION")
        super.onActivityResult(requestCode, resultCode, data)
        if (requestCode == REQ_VPN_LAYER_START && resultCode == RESULT_OK) {
            DastyabVpnService.start(this)
            Toast.makeText(this, getString(R.string.layers_vpn_connected_toast), Toast.LENGTH_SHORT).show()
        }
    }
}
