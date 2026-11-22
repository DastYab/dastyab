package com.dastyab.app

import android.app.Notification
import android.app.NotificationChannel
import android.app.NotificationManager
import android.app.PendingIntent
import android.content.Context
import android.content.Intent
import android.content.pm.PackageManager
import android.content.pm.ServiceInfo
import android.net.ConnectivityManager
import android.net.Network
import android.net.NetworkCapabilities
import android.net.NetworkRequest
import android.net.ProxyInfo
import android.net.VpnService
import android.os.Build
import android.os.ParcelFileDescriptor
import java.io.FileInputStream
import java.io.FileOutputStream
import java.io.IOException
import java.net.DatagramPacket
import java.net.DatagramSocket
import java.net.HttpURLConnection
import java.net.InetAddress
import java.net.InetSocketAddress
import java.net.Proxy
import java.net.URL
import java.util.concurrent.ConcurrentHashMap
import java.util.concurrent.ExecutorService
import java.util.concurrent.Executors
import java.util.concurrent.ScheduledExecutorService
import java.util.concurrent.TimeUnit
import java.util.concurrent.atomic.AtomicBoolean
import java.util.concurrent.atomic.AtomicInteger
import java.util.concurrent.atomic.AtomicReference
import kotlin.concurrent.thread

/**
 * DastyabVpnService — native Android VpnService supporting:
 *  • Smart Tunnel (international & Google AI Studio / Flow routes, LAN bypass)
 *  • Global VPN (full-device tunnel)
 *  • Split Tunnel Include (only selected apps routed through tunnel)
 *  • Split Tunnel Exclude (all apps routed except selected local/banking apps)
 *
 * Pure Android SDK (API 24+), zero external library dependencies.
 */
class DastyabVpnService : VpnService() {

    private var vpnInterface: ParcelFileDescriptor? = null
    private val running = AtomicBoolean(false)
    private var readerThread: Thread? = null
    private var dnsExecutor: ExecutorService? = null
    private var watchdogScheduler: ScheduledExecutorService? = null
    private val watchdogTickCount = AtomicInteger(0)
    private val watchdogHealthyStreak = AtomicInteger(0)
    private val consecutiveBlackoutTicks = AtomicInteger(0)
    private val lastNetworkTriggerMs = java.util.concurrent.atomic.AtomicLong(0L)
    private var networkCallback: ConnectivityManager.NetworkCallback? = null
    @Volatile private var activeDohUrl: String = TunnelConfig.DEFAULT_DOH_URL
    @Volatile private var activeHttpProxyPort: Int? = null
    private val tunWriteLock = Any()

    private data class CachedDnsReply(val response: ByteArray, val expiresAtMs: Long)
    private val dnsCache = ConcurrentHashMap<String, CachedDnsReply>()

    enum class State { DISCONNECTED, CONNECTING, CONNECTED }

    data class Status(
        val state: State = State.DISCONNECTED,
        val mode: TunnelConfig.Mode = TunnelConfig.Mode.SMART,
        val connectedAtMs: Long = 0L,
        val endpointLabel: String = "",
        val dnsSummary: String = "",
        val splitCount: Int = 0
    )

    companion object {
        const val ACTION_START = "com.dastyab.app.vpn.START"
        const val ACTION_STOP = "com.dastyab.app.vpn.STOP"
        const val ACTION_NEXT_LAYER = "com.dastyab.app.vpn.NEXT_LAYER"
        const val ACTION_STATE_CHANGED = "com.dastyab.app.vpn.STATE_CHANGED"

        private const val CHANNEL_ID = "dastyab_vpn_channel"
        private const val NOTIFICATION_ID = 1042

        private val currentStatus = AtomicReference(Status())

        fun getStatus(): Status = currentStatus.get()
        fun isConnected(): Boolean = currentStatus.get().state == State.CONNECTED

        fun start(context: Context) {
            startSafely(context)
        }

        fun startSafely(context: Context): Boolean {
            val intent = Intent(context, DastyabVpnService::class.java).apply {
                action = ACTION_START
            }
            return try {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
                    context.startForegroundService(intent)
                } else {
                    context.startService(intent)
                }
                true
            } catch (t: Throwable) {
                DastyabLogger.w("VpnService", t, "Unable to start foreground VPN service")
                false
            }
        }

        fun stop(context: Context) {
            val intent = Intent(context, DastyabVpnService::class.java).apply {
                action = ACTION_STOP
            }
            try {
                context.startService(intent)
            } catch (t: Throwable) {
                DastyabLogger.w("VpnService", t, "Ignoring stopService call while service is inactive")
            }
        }
    }

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        return when (intent?.action) {
            ACTION_STOP -> {
                if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O && !running.get()) {
                    enterForegroundCompat(loadSettingsSafely(), "Disconnecting…")
                }
                stopTunnel()
                stopSelf()
                START_NOT_STICKY
            }
            ACTION_NEXT_LAYER -> {
                if (UiSafety.isUserUnlockedCompat(this)) {
                    runCatching { VpnLayerStore.rotateToNextLayer(this) }
                }
                startTunnel()
                START_STICKY
            }
            else -> {
                startTunnel()
                START_STICKY
            }
        }
    }

    override fun onRevoke() {
        DastyabLogger.w("VpnService", "VPN permission revoked by system")
        stopTunnel()
        stopSelf()
        super.onRevoke()
    }

    override fun onDestroy() {
        stopTunnel()
        super.onDestroy()
    }

    private fun loadSettingsSafely(): TunnelConfig.Settings {
        if (!UiSafety.isUserUnlockedCompat(this)) {
            return TunnelConfig.Settings()
        }
        return try {
            TunnelConfig.load(this)
        } catch (t: Throwable) {
            DastyabLogger.w("VpnService", t, "Using default TunnelConfig because prefs are unavailable")
            TunnelConfig.Settings()
        }
    }

    private fun enterForegroundCompat(settings: TunnelConfig.Settings, endpointSummary: String) {
        try {
            val notification = buildNotification(settings, endpointSummary)
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.UPSIDE_DOWN_CAKE) {
                startForeground(
                    NOTIFICATION_ID,
                    notification,
                    ServiceInfo.FOREGROUND_SERVICE_TYPE_SPECIAL_USE
                )
            } else {
                startForeground(NOTIFICATION_ID, notification)
            }
        } catch (t: Throwable) {
            DastyabLogger.e("VpnService", t, "Failed to enter foreground notification state")
        }
    }

    private fun startTunnel() {
        stopTunnelInternal()
        dnsCache.clear()
        val settings = loadSettingsSafely()
        // Call startForeground immediately so Android 8–15+ never throws ForegroundServiceDidNotStartInTimeException
        // even if establish() returns null or fails below.
        enterForegroundCompat(settings, "Connecting…")

        val localHttpProxyPort = resolveLocalHttpProxyPort(settings)
        val dohLabel = settings.dohUrl.removePrefix("https://")
        val endpointSummary = when {
            localHttpProxyPort != null -> "Proxy 127.0.0.1:$localHttpProxyPort + DoH"
            settings.mode == TunnelConfig.Mode.DNS_BLACKOUT -> "DoH ($dohLabel)"
            else -> settings.parsedAnyEndpoint()?.let { "${it.protocol.uppercase()} ${it.host}:${it.port} · DoH" }
                ?: "Encrypted DoH ($dohLabel)"
        }
        val dnsSummary = "DoH + ${settings.dnsPrimary}"

        updateStatus(
            Status(
                state = State.CONNECTING,
                mode = settings.mode,
                endpointLabel = endpointSummary,
                dnsSummary = dnsSummary,
                splitCount = settings.splitPackages.size
            )
        )

        try {
            // Virtual DNS inside TUN (10.215.0.2/32): captures ALL device DNS queries and resolves
            // them over encrypted DNS-over-HTTPS (RFC 8484) with multi-DoH & protected clean-UDP fallback,
            // while allowing normal TCP/HTTPS traffic to flow cleanly without ever black-holing websites.
            val builder = Builder()
                .setSession("DastYab ${settings.mode.label}")
                .setMtu(TunnelConfig.clampMtu(settings.mtu))
                .addAddress("10.215.0.1", 30)
                .addDnsServer("10.215.0.2")
                .addRoute("10.215.0.2", 32)

            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.Q) {
                builder.setMetered(false)
                // If a local Xray/Sing-Box/Orbot/v2rayNG HTTP proxy is running on loopback,
                // chain all HTTP/HTTPS traffic through it automatically!
                if (localHttpProxyPort != null) {
                    runCatching {
                        builder.setHttpProxy(ProxyInfo.buildDirectProxy("127.0.0.1", localHttpProxyPort))
                    }
                }
            }

            // Configure per-app Split Tunneling.
            when (settings.mode) {
                TunnelConfig.Mode.SPLIT_INCLUDE -> {
                    var added = 0
                    for (pkg in settings.splitPackages) {
                        try {
                            builder.addAllowedApplication(pkg)
                            added++
                        } catch (_: PackageManager.NameNotFoundException) {
                            DastyabLogger.w("VpnService", "Split include package not found: %s", pkg)
                        } catch (_: Exception) {
                        }
                    }
                    // If no valid package was selected, fall back to excluding self so VPN stays valid.
                    if (added == 0) {
                        try { builder.addDisallowedApplication(packageName) } catch (_: Exception) {}
                    }
                }
                TunnelConfig.Mode.SPLIT_EXCLUDE -> {
                    try { builder.addDisallowedApplication(packageName) } catch (_: Exception) {}
                    for (pkg in settings.splitPackages) {
                        try {
                            builder.addDisallowedApplication(pkg)
                        } catch (_: PackageManager.NameNotFoundException) {
                            DastyabLogger.w("VpnService", "Split exclude package not found: %s", pkg)
                        } catch (_: Exception) {
                        }
                    }
                }
                TunnelConfig.Mode.SMART, TunnelConfig.Mode.GLOBAL, TunnelConfig.Mode.DNS_BLACKOUT -> {
                    // Always exclude DastYab itself so DoH / CLI / API outbound sockets never loop.
                    try { builder.addDisallowedApplication(packageName) } catch (_: Exception) {}
                }
            }

            val pfd = builder.establish()
            if (pfd == null) {
                DastyabLogger.e("VpnService", "VpnService.Builder.establish() returned null")
                stopTunnel()
                stopSelf()
                return
            }

            vpnInterface = pfd
            running.set(true)
            enterForegroundCompat(settings, endpointSummary)

            updateStatus(
                Status(
                    state = State.CONNECTED,
                    mode = settings.mode,
                    connectedAtMs = System.currentTimeMillis(),
                    endpointLabel = endpointSummary,
                    dnsSummary = dnsSummary,
                    splitCount = settings.splitPackages.size
                )
            )
            DastyabLogger.i(
                "VpnService",
                "VPN connected — mode=%s dns=%s proxyPort=%s mtu=%d split=%d",
                settings.mode.name, dnsSummary, localHttpProxyPort?.toString() ?: "none", settings.mtu, settings.splitPackages.size
            )

            activeDohUrl = settings.dohUrl
            activeHttpProxyPort = localHttpProxyPort
            dnsExecutor = Executors.newFixedThreadPool(6)
            startWatchdogIfEnabled(settings)

            // Forward every intercepted DNS query over encrypted DoH (with multi-fallback + cache)
            // and write valid IPv4/UDP DNS responses back into the TUN interface.
            readerThread = thread(isDaemon = true, name = "dastyab-tun") {
                val buf = ByteArray(settings.mtu.coerceAtLeast(1500))
                try {
                    FileInputStream(pfd.fileDescriptor).use { input ->
                        FileOutputStream(pfd.fileDescriptor).use { output ->
                            while (running.get()) {
                                val read = input.read(buf)
                                if (read < 0) break
                                if (read == 0) {
                                    Thread.sleep(15)
                                    continue
                                }
                                FailoverWatchdog.passiveSentinel.recordOutbound(read.toLong())
                                val req = DnsPacketCodec.parseIpv4UdpDnsQuery(buf, read)
                                if (req != null) {
                                    val exec = dnsExecutor
                                    if (exec != null && !exec.isShutdown) {
                                        exec.execute {
                                            val respBytes = resolveDnsCachedOrNetwork(
                                                req.dnsPayload,
                                                activeDohUrl,
                                                settings.dnsPrimary,
                                                settings.dnsSecondary
                                            )
                                            if (respBytes != null && running.get()) {
                                                val ipPacket = DnsPacketCodec.buildIpv4UdpDnsResponse(req, respBytes)
                                                FailoverWatchdog.passiveSentinel.recordInbound(ipPacket.size.toLong())
                                                synchronized(tunWriteLock) {
                                                    try {
                                                        output.write(ipPacket)
                                                    } catch (_: IOException) {}
                                                }
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                } catch (_: IOException) {
                    // Expected when TUN closes during disconnect.
                } catch (_: InterruptedException) {
                    // Clean shutdown.
                }
            }
        } catch (e: Exception) {
            DastyabLogger.e("VpnService", e, "Failed to establish VPN tunnel")
            stopTunnel()
            stopSelf()
        }
    }

    /**
     * Add public IPv4 routes covering international / Google / Cloudflare address space
     * while leaving RFC1918 LAN ranges (10.0.0.0/8, 172.16.0.0/12, 192.168.0.0/16) direct.
     */
    private fun addPublicInternetRoutes(builder: Builder) {
        val publicCidrs = listOf(
            "1.0.0.0" to 8,
            "2.0.0.0" to 7,
            "4.0.0.0" to 6,
            "8.0.0.0" to 7,
            "11.0.0.0" to 8,
            "12.0.0.0" to 6,
            "16.0.0.0" to 4,
            "32.0.0.0" to 3,
            "64.0.0.0" to 2,
            "128.0.0.0" to 3,
            "160.0.0.0" to 5,
            "168.0.0.0" to 6,
            "172.0.0.0" to 12,
            "172.32.0.0" to 11,
            "172.64.0.0" to 10,
            "172.128.0.0" to 9,
            "173.0.0.0" to 8,
            "174.0.0.0" to 7,
            "176.0.0.0" to 4,
            "192.0.0.0" to 9,
            "192.128.0.0" to 11,
            "192.160.0.0" to 13,
            "192.169.0.0" to 16,
            "192.170.0.0" to 15,
            "192.172.0.0" to 14,
            "192.176.0.0" to 12,
            "192.192.0.0" to 10,
            "193.0.0.0" to 8,
            "194.0.0.0" to 7,
            "196.0.0.0" to 6,
            "200.0.0.0" to 5,
            "208.0.0.0" to 4
        )
        for ((addr, prefix) in publicCidrs) {
            builder.addRoute(addr, prefix)
        }
    }

    private fun stopTunnel() {
        stopTunnelInternal()
        runCatching {
            if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.N) {
                stopForeground(STOP_FOREGROUND_REMOVE)
            } else {
                @Suppress("DEPRECATION")
                stopForeground(true)
            }
        }
        val settings = loadSettingsSafely()
        updateStatus(Status(state = State.DISCONNECTED, mode = settings.mode))
        DastyabLogger.i("VpnService", "VPN disconnected")
    }

    private fun stopTunnelInternal() {
        running.set(false)
        unregisterNetworkMonitor()
        watchdogScheduler?.shutdownNow()
        watchdogScheduler = null
        FailoverWatchdog.reset(active = false)
        readerThread?.interrupt()
        readerThread = null
        dnsExecutor?.shutdownNow()
        dnsExecutor = null
        activeHttpProxyPort = null
        try {
            vpnInterface?.close()
        } catch (_: IOException) {}
        vpnInterface = null
    }

    /**
     * Starts the Adaptive Self-Healing Watchdog (15s on stall/drop → 60s warmup → 240s healthy)
     * plus 10s passive half-open sentinel observer & OS NetworkCallback listener.
     */
    private fun startWatchdogIfEnabled(settings: TunnelConfig.Settings) {
        unregisterNetworkMonitor()
        watchdogScheduler?.shutdownNow()
        watchdogScheduler = null
        watchdogTickCount.set(0)
        watchdogHealthyStreak.set(0)
        consecutiveBlackoutTicks.set(0)
        if (!settings.watchdogEnabled) {
            FailoverWatchdog.reset(active = false, dohUrl = activeDohUrl)
            return
        }
        FailoverWatchdog.reset(active = true, dohUrl = activeDohUrl)
        val sched = Executors.newSingleThreadScheduledExecutor { r ->
            Thread(r, "dastyab-watchdog").apply { isDaemon = true }
        }
        watchdogScheduler = sched
        registerNetworkMonitor(sched)

        // Lightweight passive stall observer every 10 seconds (zero network cost)
        sched.scheduleAtFixedRate(
            {
                if (!running.get()) return@scheduleAtFixedRate
                if (FailoverWatchdog.passiveSentinel.evaluate() == FailoverWatchdog.SentinelVerdict.STALLED) {
                    DastyabLogger.w("Watchdog", "Passive Liveness Sentinel detected half-open stall — triggering early heal tick")
                    sched.execute { if (running.get()) runWatchdogTick(sched, reschedule = false) }
                }
            },
            10L,
            10L,
            TimeUnit.SECONDS
        )

        scheduleNextWatchdogTick(sched, FailoverWatchdog.CONTINUOUS_PROBE_INTERVAL_SECONDS)
    }

    private fun scheduleNextWatchdogTick(sched: ScheduledExecutorService, delaySeconds: Long) {
        if (!running.get() || sched.isShutdown) return
        runCatching {
            sched.schedule(
                {
                    if (!running.get()) return@schedule
                    runWatchdogTick(sched, reschedule = true)
                },
                delaySeconds.coerceIn(10L, 300L),
                TimeUnit.SECONDS
            )
        }
    }

    private fun registerNetworkMonitor(sched: ScheduledExecutorService) {
        runCatching {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
            val req = NetworkRequest.Builder()
                .addCapability(NetworkCapabilities.NET_CAPABILITY_INTERNET)
                .build()
            val cb = object : ConnectivityManager.NetworkCallback() {
                override fun onAvailable(network: Network) {
                    triggerDebouncedNetworkProbe(sched)
                }

                override fun onLost(network: Network) {
                    triggerDebouncedNetworkProbe(sched)
                }
            }
            cm.registerNetworkCallback(req, cb)
            networkCallback = cb
        }
    }

    private fun unregisterNetworkMonitor() {
        val cb = networkCallback ?: return
        networkCallback = null
        runCatching {
            val cm = getSystemService(Context.CONNECTIVITY_SERVICE) as? ConnectivityManager ?: return
            cm.unregisterNetworkCallback(cb)
        }
    }

    private fun triggerDebouncedNetworkProbe(sched: ScheduledExecutorService) {
        val now = System.currentTimeMillis()
        val prev = lastNetworkTriggerMs.get()
        if (now - prev < 5000L || !lastNetworkTriggerMs.compareAndSet(prev, now)) return
        if (!running.get() || sched.isShutdown) return
        runCatching {
            sched.schedule({ if (running.get()) runWatchdogTick(sched, reschedule = false) }, 2L, TimeUnit.SECONDS)
        }
    }

    private fun runWatchdogTick(sched: ScheduledExecutorService, reschedule: Boolean = true) {
        val tick = watchdogTickCount.incrementAndGet()
        val prev = FailoverWatchdog.getSnapshot()
        var nextDelay = FailoverWatchdog.CONTINUOUS_PROBE_INTERVAL_SECONDS
        try {
            val check = ReachabilityVerifier.verifyAll(timeoutMs = 2800)
            val sentinelStalled = FailoverWatchdog.passiveSentinel.evaluate() == FailoverWatchdog.SentinelVerdict.STALLED
            val currentSettings = loadSettingsSafely()
            val blackoutStreak = if (check.internet.isOk) {
                consecutiveBlackoutTicks.set(0)
                0
            } else {
                consecutiveBlackoutTicks.incrementAndGet()
            }

            val rawObservedMs = check.aiStudio.latencyMs.takeIf { it >= 0 } ?: check.internet.latencyMs
            val latStatus = FailoverWatchdog.latencyTracker.record(rawObservedMs)

            val eval = FailoverWatchdog.evaluateHealthAndLatency(
                internetOk = check.internet.isOk,
                aiStudioOk = check.aiStudio.isOk,
                flowOk = check.flow.isOk,
                latencyMs = rawObservedMs,
                sentinelStalled = sentinelStalled,
                consecutiveBlackoutTicks = blackoutStreak,
                highLatencyStreak = latStatus.highLatencyStreak,
                ewmaLatencyMs = latStatus.ewmaMs,
                currentMode = currentSettings.mode
            )
            val action = eval.action

            var swaps = prev.swapCount
            var harvests = prev.backgroundHarvestCount
            var autoBlackoutEscalated = prev.autoBlackoutEscalated
            var fastestRegionLabel = prev.fastestRegionLabel
            val netKey = runCatching { AutopilotBrain.detectNetworkContextKey(this) }.getOrDefault("default")
            val activeLayer = runCatching { VpnLayerStore.getActiveLayer(this) }.getOrNull()
            val summary: String

            val geoMask = (if (check.internet.isOk) AutopilotBrain.GEO_CLEAR_WEB else 0) or
                (if (check.aiStudio.isOk) AutopilotBrain.GEO_CLEAR_AISTUDIO else 0) or
                (if (check.flow.isOk) AutopilotBrain.GEO_CLEAR_FLOW else 0)

            val activeArmId = activeLayer?.configUri?.takeIf { it.isNotBlank() } ?: activeDohUrl
            val activeProto = activeLayer?.configUri?.takeIf { it.isNotBlank() }?.let { UniversalConfig.protocolOf(it) } ?: "doh"
            val rttSample = rawObservedMs.toDouble()

            if (action == FailoverWatchdog.Action.SWAP_DOH_OR_LAYER) {
                watchdogHealthyStreak.set(0)
                BrutalAntiGeoblockEngine.recordDpiBlockAndEscalate()
                runCatching {
                    AutopilotBrain.ensureLoaded(this)
                    AutopilotBrain.recordOutcome(
                        netKey, activeArmId, activeProto,
                        success = (eval.reason == FailoverWatchdog.HealReason.LATENCY_EXCEEDED_300MS),
                        rttMs = if (eval.reason == FailoverWatchdog.HealReason.LATENCY_EXCEEDED_300MS) rttSample.takeIf { it > 0 } else null,
                        persistContext = this
                    )
                }

                // Parallel multi-region latency benchmark to pick fastest sub-300ms DoH / edge region
                val regionBench = runCatching { CleanEndpointScout.benchmarkMultiRegionParallel(timeoutMs = 1500) }.getOrDefault(emptyList())
                val bestRegion = regionBench.firstOrNull { !it.target.dohUrl.isNullOrBlank() }
                if (regionBench.isNotEmpty()) {
                    fastestRegionLabel = CleanEndpointScout.formatRegionBenchmarkSummary(regionBench)
                }

                val nextDoh = bestRegion?.target?.dohUrl?.takeIf { !it.equals(activeDohUrl, ignoreCase = true) }
                    ?: FailoverWatchdog.nextFallbackDoh(activeDohUrl)
                activeDohUrl = nextDoh
                dnsCache.clear()
                TunnelConfig.saveDohAndDns(this, dohUrl = nextDoh, primaryDns = null)
                swaps++

                if (eval.shouldEscalateBlackout) {
                    TunnelConfig.saveMode(this, TunnelConfig.Mode.DNS_BLACKOUT)
                    autoBlackoutEscalated = true
                }

                val currentLayerId = activeLayer?.id.orEmpty()
                val backup = runCatching { VpnLayerStore.findFastestBackupLayer(this, currentLayerId, timeoutMs = 1500) }.getOrNull()
                summary = when {
                    eval.shouldEscalateBlackout ->
                        "Blackout Fallback → DNS Blackout VPN (${nextDoh.removePrefix("https://")} · #$tick)"
                    backup != null && backup.layer.dohUrl != nextDoh &&
                        (eval.reason != FailoverWatchdog.HealReason.LATENCY_EXCEEDED_300MS || backup.latencyMs < rawObservedMs) -> {
                        activeDohUrl = backup.layer.dohUrl
                        VpnLayerStore.activateLayer(this, backup.layer, restartIfConnected = false)
                        "Auto-healed → ${backup.layer.name} (${backup.latencyMs}ms · #$tick)"
                    }
                    eval.reason == FailoverWatchdog.HealReason.LATENCY_EXCEEDED_300MS ->
                        "300ms SLA Switch (${rawObservedMs}ms) → ${bestRegion?.target?.label ?: nextDoh.removePrefix("https://")} · #$tick"
                    else ->
                        "Auto-swapped DoH → ${nextDoh.removePrefix("https://")} (#$tick)"
                }
                FailoverWatchdog.passiveSentinel.reset()
                FailoverWatchdog.latencyTracker.reset()
                nextDelay = FailoverWatchdog.recommendedDelaySeconds(0, suspect = true, observedLatencyMs = rawObservedMs)
                DastyabLogger.w("Watchdog", "Heal triggered (%s) — %s", eval.reason.name, summary)
            } else {
                val streak = watchdogHealthyStreak.incrementAndGet()
                if (rawObservedMs in 1..FailoverWatchdog.LATENCY_SWITCH_THRESHOLD_MS) {
                    BrutalAntiGeoblockEngine.recordDpiCleanPass()
                }
                runCatching {
                    AutopilotBrain.ensureLoaded(this)
                    AutopilotBrain.recordOutcome(
                        netKey, activeArmId, activeProto, success = true,
                        rttMs = rttSample.takeIf { it > 0 }, geoMaskObserved = geoMask, persistContext = this
                    )
                }
                nextDelay = FailoverWatchdog.recommendedDelaySeconds(streak, suspect = false, observedLatencyMs = rawObservedMs)
                summary = "Healthy (${rawObservedMs}ms) · #$tick · next ${nextDelay}s"
            }

            // Quiet background harvest if pool is empty or every 6 ticks
            val poolSize = TunnelConfig.loadHarvestedConfigs(this).size
            if (FailoverWatchdog.shouldRunBackgroundHarvest(tick, poolSize)) {
                try {
                    val harvested = ConfigHarvester.harvestResilient(this)
                    if (harvested.configs.isNotEmpty()) {
                        TunnelConfig.saveHarvestedConfigs(this, harvested.configs)
                        harvests++
                    }
                } catch (_: Exception) {}
            }

            FailoverWatchdog.update(
                FailoverWatchdog.Snapshot(
                    active = true,
                    healthy = action == FailoverWatchdog.Action.KEEP_CURRENT,
                    lastCheckMs = System.currentTimeMillis(),
                    lastLatencyMs = rawObservedMs,
                    checkCount = tick,
                    swapCount = swaps,
                    backgroundHarvestCount = harvests,
                    activeDohUrl = activeDohUrl,
                    lastSummary = summary,
                    nextIntervalSeconds = nextDelay,
                    healthyStreak = watchdogHealthyStreak.get(),
                    suspectState = action == FailoverWatchdog.Action.SWAP_DOH_OR_LAYER,
                    ewmaLatencyMs = eval.ewmaLatencyMs,
                    highLatencyStreak = eval.highLatencyStreak,
                    healReason = eval.reason.name,
                    autoBlackoutEscalated = autoBlackoutEscalated,
                    fastestRegionLabel = fastestRegionLabel
                )
            )
            val intent = Intent(ACTION_STATE_CHANGED).setPackage(packageName)
            runCatching { sendBroadcast(intent) }
            DastyabWidgetProvider.updateAllWidgets(this)
        } catch (e: Exception) {
            DastyabLogger.w("Watchdog", "Watchdog tick error: %s", e.message ?: "unknown")
        } finally {
            if (reschedule) scheduleNextWatchdogTick(sched, nextDelay)
        }
    }

    /**
     * Resolves an HTTP proxy port on loopback for Android 10+ `VpnService.Builder.setHttpProxy`.
     * Priority: active DastYab [LocalProxyService] bridge (which can also translate SOCKS5 -> HTTP),
     * explicit HTTP proxy port from [TunnelConfig.Settings], or well-known loopback ports.
     */
    private fun resolveLocalHttpProxyPort(settings: TunnelConfig.Settings): Int? {
        LocalProxyService.activePort()?.let { return it }
        if (settings.upstreamProxyScheme == TunnelConfig.ProxyScheme.HTTP &&
            settings.upstreamProxyPort in 1..65535 &&
            (settings.upstreamProxyHost == "127.0.0.1" || settings.upstreamProxyHost == "localhost")
        ) {
            if (CleanEndpointScout.probeTcpLatency("127.0.0.1", settings.upstreamProxyPort, 140) >= 0) {
                return settings.upstreamProxyPort
            }
        }
        val ports = listOf(10809, 12334, 2081, 8118, 7890, 8080)
        for (port in ports) {
            if (CleanEndpointScout.probeTcpLatency("127.0.0.1", port, 120) >= 0) {
                return port
            }
        }
        return null
    }

    /**
     * Fast cached DNS resolver with multi-DoH + protected clean-UDP fallback so DNS never stalls
     * and repeated lookups resolve in <1ms.
     */
    private fun resolveDnsCachedOrNetwork(
        query: ByteArray,
        dohUrl: String,
        primaryDns: String,
        secondaryDns: String
    ): ByteArray? {
        val domain = DnsPacketCodec.extractQueryDomain(query).lowercase()
        val qtype = DnsPacketCodec.extractQueryType(query)
        val cacheKey = "$domain:$qtype"
        val now = System.currentTimeMillis()
        if (domain.isNotEmpty()) {
            dnsCache[cacheKey]?.let { cached ->
                if (cached.expiresAtMs > now && cached.response.size >= 12 && query.size >= 2) {
                    // Patch the 2-byte DNS Transaction ID to match the incoming query
                    val patched = cached.response.copyOf()
                    patched[0] = query[0]
                    patched[1] = query[1]
                    return patched
                }
            }
        }

        val rules = if (UiSafety.isUserUnlockedCompat(this)) {
            runCatching { DomainDnsRules.load(this) }.getOrNull() ?: DomainDnsRules.Rules()
        } else {
            DomainDnsRules.Rules()
        }
        val bypassLocal = DomainDnsRules.shouldBypassToLocalDns(domain, rules)

        // Prevent carrier IPv6 from bypassing IPv4-only SOCKS5/HTTP proxy chains:
        // return clean RFC 4074 NODATA for non-bypassed AAAA queries while a proxy bridge is active.
        if (!bypassLocal && qtype == DnsPacketCodec.QTYPE_AAAA && activeHttpProxyPort != null) {
            DnsPacketCodec.buildEmptyNoDataResponse(query)?.let { return it }
        }

        val fresh = if (bypassLocal) {
            // Iranian (.ir / banking / local) or custom bypass domain: resolve via fast protected UDP DNS first
            resolveDnsBypassLocalFirst(query, dohUrl, primaryDns, secondaryDns)
        } else {
            resolveDnsOverDohOrUdp(query, dohUrl, primaryDns, secondaryDns)
        }
        if (fresh != null && domain.isNotEmpty()) {
            if (dnsCache.size > 400) dnsCache.clear()
            dnsCache[cacheKey] = CachedDnsReply(fresh.copyOf(), now + 45_000L)
        }
        return fresh
    }

    private fun resolveDnsBypassLocalFirst(
        query: ByteArray,
        dohUrl: String,
        primaryDns: String,
        secondaryDns: String
    ): ByteArray? {
        val udpChain = listOf(primaryDns, secondaryDns, "1.1.1.1", "8.8.8.8").distinct()
        for (ip in udpChain) {
            queryProtectedUdpDns(ip, query)?.let { return it }
        }
        return queryDoh(dohUrl, query)
    }

    /**
     * Resolves a raw DNS wire query over RFC 8484 DNS-over-HTTPS first (immune to UDP-53 poisoning),
     * trying multiple DoH providers before falling back to protected clean UDP-53 sockets.
     */
    private fun resolveDnsOverDohOrUdp(
        query: ByteArray,
        dohUrl: String,
        primaryDns: String,
        secondaryDns: String
    ): ByteArray? {
        val dohChain = (listOf(dohUrl) + BrutalAntiGeoblockEngine.NO_ECS_DOH_URLS).distinct()
        for (url in dohChain) {
            queryDoh(url, query)?.let { return it }
        }
        val udpChain = listOf(primaryDns, secondaryDns, "1.1.1.1", "9.9.9.9", "8.8.8.8").distinct()
        for (ip in udpChain) {
            queryProtectedUdpDns(ip, query)?.let { return it }
        }
        return null
    }

    private fun queryDoh(dohUrl: String, query: ByteArray): ByteArray? {
        val proxyPort = activeHttpProxyPort ?: LocalProxyService.activePort()
        val proxyAttempts = if (proxyPort != null) {
            listOf(Proxy(Proxy.Type.HTTP, InetSocketAddress("127.0.0.1", proxyPort)), Proxy.NO_PROXY)
        } else {
            listOf(Proxy.NO_PROXY)
        }
        val (padBlock, padJitter) = BrutalAntiGeoblockEngine.computeAdaptiveDohPaddingTarget()
        val paddedQuery = DnsPacketCodec.padDnsQueryEdns0(query, blockSize = padBlock, extraJitterBytes = padJitter)
        val payloads = if (paddedQuery.contentEquals(query)) listOf(query) else listOf(paddedQuery, query)

        for (proxy in proxyAttempts) {
            for (wireQuery in payloads) {
                var conn: HttpURLConnection? = null
                val res = try {
                    conn = (URL(dohUrl).openConnection(proxy) as HttpURLConnection).apply {
                        requestMethod = "POST"
                        doOutput = true
                        connectTimeout = 2600
                        readTimeout = 2600
                        setRequestProperty("Content-Type", "application/dns-message")
                        setRequestProperty("Accept", "application/dns-message")
                    }
                    conn.outputStream.use { it.write(wireQuery) }
                    if (conn.responseCode == 200) {
                        conn.inputStream.use { it.readBytes() }.takeIf { it.size >= 12 }
                    } else {
                        null
                    }
                } catch (_: Exception) {
                    null
                } finally {
                    conn?.disconnect()
                }
                if (res != null) return res
            }
        }
        return null
    }

    private fun queryProtectedUdpDns(dnsIp: String, query: ByteArray): ByteArray? {
        return try {
            DatagramSocket().use { socket ->
                protect(socket)
                socket.soTimeout = 2200
                val addr = InetAddress.getByName(dnsIp)
                socket.send(DatagramPacket(query, query.size, addr, 53))
                val respBuf = ByteArray(1500)
                val resp = DatagramPacket(respBuf, respBuf.size)
                socket.receive(resp)
                if (resp.length >= 12) respBuf.copyOf(resp.length) else null
            }
        } catch (_: Exception) {
            null
        }
    }

    private fun updateStatus(status: Status) {
        currentStatus.set(status)
        val intent = Intent(ACTION_STATE_CHANGED).setPackage(packageName)
        runCatching { sendBroadcast(intent) }
        try {
            DastyabWidgetProvider.updateAllWidgets(this)
        } catch (_: Exception) {}
    }

    private fun buildNotification(settings: TunnelConfig.Settings, endpointSummary: String): Notification {
        if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            val nm = getSystemService(Context.NOTIFICATION_SERVICE) as NotificationManager
            val channel = NotificationChannel(
                CHANNEL_ID,
                "DastYab VPN Tunnel",
                NotificationManager.IMPORTANCE_LOW
            ).apply {
                description = "Active DastYab Smart / Split VPN tunnel status"
            }
            nm.createNotificationChannel(channel)
        }

        val openIntent = PendingIntent.getActivity(
            this,
            0,
            Intent(this, MainActivity::class.java),
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val stopPending = PendingIntent.getService(
            this,
            1,
            Intent(this, DastyabVpnService::class.java).apply { action = ACTION_STOP },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )
        val nextLayerPending = PendingIntent.getService(
            this,
            2,
            Intent(this, DastyabVpnService::class.java).apply { action = ACTION_NEXT_LAYER },
            PendingIntent.FLAG_IMMUTABLE or PendingIntent.FLAG_UPDATE_CURRENT
        )

        val builder = if (Build.VERSION.SDK_INT >= Build.VERSION_CODES.O) {
            Notification.Builder(this, CHANNEL_ID)
        } else {
            @Suppress("DEPRECATION")
            Notification.Builder(this)
        }

        val activeLayer = if (UiSafety.isUserUnlockedCompat(this)) {
            runCatching { VpnLayerStore.getActiveLayer(this) }.getOrNull()
        } else {
            null
        }
        val layerName = activeLayer?.name ?: "Smart Tunnel"
        return builder
            .setContentTitle("DastYab · $layerName")
            .setContentText("${settings.mode.label} · $endpointSummary")
            .setSmallIcon(R.drawable.ic_notification_vpn)
            .setOngoing(true)
            .setContentIntent(openIntent)
            .addAction(
                Notification.Action.Builder(
                    null,
                    "Next Layer",
                    nextLayerPending
                ).build()
            )
            .addAction(
                Notification.Action.Builder(
                    null,
                    "Disconnect",
                    stopPending
                ).build()
            )
            .build()
    }
}
