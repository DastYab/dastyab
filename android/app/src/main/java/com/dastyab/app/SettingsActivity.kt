package com.dastyab.app

import android.content.Intent
import android.os.Bundle
import android.view.View
import android.widget.AdapterView
import android.widget.ArrayAdapter
import android.widget.Button
import android.widget.CheckBox
import android.widget.CompoundButton
import android.widget.LinearLayout
import android.widget.Spinner
import android.widget.TextView
import android.widget.Toast
import java.io.File

/**
 * SettingsActivity — app settings screen:
 *  • Log file level selector (VERBOSE..ERROR) via DastyabLogger.setMinFileLevel()
 *  • Auto-update binary toggle (checked on app start in MainActivity)
 *  • Clear logs / crash logs / command history buttons
 *  • Force re-download binary button
 *  • About button
 */
class SettingsActivity : DastyabActivity() {

    private lateinit var levelSpinner: Spinner
    private lateinit var cbAutoUpdate: CheckBox
    private lateinit var tvStatus: TextView

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContentView(R.layout.activity_settings)

        val tvCurrentTheme = findViewById<TextView>(R.id.tvCurrentTheme)
        val btnChooseTheme = findViewById<Button>(R.id.btnChooseTheme)
        val tvCurrentLanguage = findViewById<TextView>(R.id.tvCurrentLanguage)
        val btnChooseLanguage = findViewById<Button>(R.id.btnChooseLanguage)

        tvCurrentTheme.text = getString(
            R.string.settings_current_theme_format,
            ThemeManager.localizedName(this, ThemeManager.getSelectedTheme(this))
        )
        tvCurrentLanguage.text = getString(
            R.string.settings_current_lang_format,
            LocaleHelper.displayName(LocaleHelper.getLanguage(this))
        )

        btnChooseTheme.setOnClickListener {
            ThemeManager.showThemePickerDialog(this) {
                recreate()
            }
        }
        btnChooseLanguage.setOnClickListener {
            LocaleHelper.showLanguagePickerDialog(this) {
                DastyabWidgetProvider.updateAllWidgets(this)
                recreate()
            }
        }

        levelSpinner = findViewById(R.id.spinnerLogLevel)
        cbAutoUpdate = findViewById(R.id.cbAutoUpdate)
        tvStatus = findViewById(R.id.tvSettingsStatus)
        val btnClearLogs = findViewById<Button>(R.id.btnClearLogs)
        val btnClearCrashLogs = findViewById<Button>(R.id.btnClearCrashLogs)
        val btnClearHistory = findViewById<Button>(R.id.btnClearHistory)
        val btnForceRedownload = findViewById<Button>(R.id.btnForceRedownload)
        val btnAbout = findViewById<Button>(R.id.btnSettingsAbout)

        // ── Log level spinner ──
        val levels = listOf("VERBOSE", "DEBUG", "INFO", "WARN", "ERROR")
        val adapter = ArrayAdapter(this, android.R.layout.simple_spinner_item, levels)
        adapter.setDropDownViewResource(android.R.layout.simple_spinner_dropdown_item)
        levelSpinner.adapter = adapter

        val current = try {
            DastyabLogger.getCurrentMinFileLevel().name
        } catch (_: Throwable) { "DEBUG" }
        levelSpinner.setSelection(levels.indexOf(current).coerceAtLeast(0))

        var initialSelection = true
        levelSpinner.onItemSelectedListener = object : AdapterView.OnItemSelectedListener {
            override fun onItemSelected(parent: AdapterView<*>?, view: View?, position: Int, id: Long) {
                if (initialSelection) {
                    initialSelection = false
                    return
                }
                val name = levels[position]
                val level = try {
                    DastyabLogger.LogLevel.valueOf(name)
                } catch (_: Throwable) { return }
                DastyabLogger.setMinFileLevel(level)
                persistPref(PREF_LOG_LEVEL, name)
                DastyabLogger.i("Settings", "Log file level set to %s", name)
                setStatus(getString(R.string.settings_status_log_level, name))
            }
            override fun onNothingSelected(parent: AdapterView<*>?) {}
        }

        // ── Auto-update toggle ──
        cbAutoUpdate.visibility = View.VISIBLE
        cbAutoUpdate.isChecked = AppAutoUpdater.isAutoUpdateEnabled(this)
        cbAutoUpdate.setOnCheckedChangeListener { _: CompoundButton, isChecked: Boolean ->
            AppAutoUpdater.setAutoUpdateEnabled(this, isChecked)
            val msg = getString(
                if (isChecked) R.string.app_update_status_enabled else R.string.app_update_status_disabled
            )
            setStatus(msg)
            Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
        }

        // ── Clear logs ──
        btnClearLogs.setOnClickListener {
            val files = DastyabLogger.getLogFiles()
            var n = 0
            for (f in files) if (f.delete()) n++
            DastyabLogger.i("Settings", "Cleared %d log files", n)
            val msg = getString(R.string.settings_deleted_logs, n)
            Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
            setStatus(msg)
        }

        // ── Clear crash logs ──
        btnClearCrashLogs.setOnClickListener {
            val n = CrashHandler.clearCrashFiles()
            DastyabLogger.i("Settings", "Cleared %d crash files", n)
            val msg = getString(R.string.settings_deleted_crash_logs, n)
            Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
            setStatus(msg)
        }

        // ── Clear command history ──
        btnClearHistory.setOnClickListener {
            CommandHistory.clear()
            val msg = getString(R.string.settings_history_cleared)
            Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
            setStatus(msg)
        }

        // ── Check & install app updates ──
        btnForceRedownload.setOnClickListener {
            btnForceRedownload.isEnabled = false
            setStatus(getString(R.string.app_update_status_checking))
            kotlin.concurrent.thread(isDaemon = true, name = "dastyab-settings-update") {
                val outcome = AppAutoUpdater.checkAndDownloadIfNeeded(applicationContext, force = true)
                runOnUiThread {
                    if (!UiSafety.isActivityAlive(this)) return@runOnUiThread
                    btnForceRedownload.isEnabled = true
                    when (outcome) {
                        is AppAutoUpdater.CheckOutcome.UpToDate -> {
                            val msg = getString(R.string.app_update_status_uptodate, outcome.remoteTag)
                            setStatus(msg)
                            Toast.makeText(this, msg, Toast.LENGTH_SHORT).show()
                        }
                        is AppAutoUpdater.CheckOutcome.ReadyToInstall -> {
                            setStatus("${outcome.remoteTag} ready: ${outcome.assetName}")
                            pendingInstallApk = outcome.apkFile
                            UiSafety.safeShowDialog(
                                this,
                                android.app.AlertDialog.Builder(this)
                                    .setTitle(getString(R.string.app_update_ready_title, outcome.remoteTag))
                                    .setMessage(
                                        getString(
                                            R.string.app_update_ready_msg,
                                            outcome.currentVersion,
                                            outcome.remoteTag,
                                            outcome.assetName
                                        )
                                    )
                                    .setPositiveButton(getString(R.string.app_update_install_now)) { _, _ ->
                                        if (!AppAutoUpdater.launchInstallerOrRequestPermission(this, outcome.apkFile)) {
                                            Toast.makeText(
                                                this,
                                                getString(R.string.app_update_permission_msg),
                                                Toast.LENGTH_LONG
                                            ).show()
                                        } else {
                                            pendingInstallApk = null
                                        }
                                    }
                                    .setNeutralButton(getString(R.string.app_update_open_releases)) { _, _ ->
                                        UiSafety.safeStartActivity(
                                            this,
                                            Intent(Intent.ACTION_VIEW, android.net.Uri.parse(AppAutoUpdater.RELEASE_LATEST_WEB))
                                        )
                                    }
                                    .setNegativeButton(getString(R.string.app_update_later), null)
                            )
                        }
                        is AppAutoUpdater.CheckOutcome.Failed -> {
                            setStatus("${outcome.message} — opening Releases")
                            val opened = UiSafety.safeStartActivity(
                                this,
                                Intent(Intent.ACTION_VIEW, android.net.Uri.parse(AppAutoUpdater.RELEASE_LATEST_WEB))
                            )
                            if (!opened) {
                                setStatus(getString(R.string.settings_releases_hint))
                            }
                        }
                    }
                }
            }
        }

        // ── About ──
        btnAbout.setOnClickListener {
            UiSafety.safeStartActivity(this, Intent(this, AboutActivity::class.java))
        }
    }

    private var pendingInstallApk: File? = null

    override fun onResume() {
        super.onResume()
        val pending = pendingInstallApk
        if (pending != null && pending.isFile) {
            if (android.os.Build.VERSION.SDK_INT < android.os.Build.VERSION_CODES.O ||
                packageManager.canRequestPackageInstalls()
            ) {
                pendingInstallApk = null
                AppAutoUpdater.launchInstallerOrRequestPermission(this, pending)
            }
        }
    }

    private fun getPrefs() = getSharedPreferences(PREFS_NAME, MODE_PRIVATE)

    private fun persistPref(key: String, value: String) {
        getPrefs().edit().putString(key, value).apply()
    }

    private fun persistPref(key: String, value: Boolean) {
        getPrefs().edit().putBoolean(key, value).apply()
    }

    private fun setStatus(msg: String) {
        tvStatus.text = msg
    }

    companion object {
        const val PREFS_NAME = "dastyab_settings"
        const val PREF_LOG_LEVEL = "log_level"
        const val PREF_AUTO_UPDATE = "auto_update"
    }
}
