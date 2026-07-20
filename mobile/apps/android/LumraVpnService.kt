// LumraVpnService — the monitor-only VpnService that runs Lumra's diagnosis core
// on Android (host mode B: standalone monitoring, no circumvention). It
// establishes a local tunnel, reads every IP packet, feeds it to the Lumra
// cockpit, and writes it straight back out untouched. Lumra observes; it never
// holds, modifies, routes, or re-injects — that is warren's role.
//
// Import the gomobile-built binding produced by:
//   gomobile bind -target=android -o lumra.aar github.com/croc100/lumra/mobile
// Add lumra.aar to the module's dependencies; `mobile` below is the generated
// Java/Kotlin package (mobile.Mobile.newCockpit(), mobile.Cockpit).

package net.crode.lumra

import android.content.Intent
import android.net.VpnService
import android.os.ParcelFileDescriptor
import kotlinx.coroutines.*
import mobile.Cockpit
import mobile.Mobile
import java.io.FileInputStream
import java.io.FileOutputStream
import java.nio.ByteBuffer

class LumraVpnService : VpnService() {
    private var tunnel: ParcelFileDescriptor? = null
    private var scope: CoroutineScope? = null
    private lateinit var cockpit: Cockpit

    override fun onStartCommand(intent: Intent?, flags: Int, startId: Int): Int {
        if (intent?.action == ACTION_STOP) {
            stopSelf()
            return START_NOT_STICKY
        }
        start()
        return START_STICKY
    }

    private fun start() {
        cockpit = Mobile.newCockpit()

        // Capture all traffic so Lumra sees it; pass it through untouched. Public
        // resolvers keep DNS flowing through the observed path.
        val builder = Builder()
            .setSession("Lumra (monitor-only)")
            .addAddress("10.111.0.2", 24)
            .addAddress("fd00:111::2", 64)
            .addRoute("0.0.0.0", 0)
            .addRoute("::", 0)
            .addDnsServer("1.1.1.1")
            .addDnsServer("8.8.8.8")
        // Exclude ourselves so the monitor loop can't observe its own writes.
        builder.addDisallowedApplication(packageName)

        val fd = builder.establish() ?: run { stopSelf(); return }
        tunnel = fd

        val job = SupervisorJob()
        val cs = CoroutineScope(Dispatchers.IO + job)
        scope = cs
        cs.launch { readLoop(fd) }
        cs.launch { publishLoop() }
    }

    // readLoop drains the tunnel: each packet is fed to the cockpit (observe) then
    // written straight back out (pass through).
    private suspend fun readLoop(fd: ParcelFileDescriptor) {
        val input = FileInputStream(fd.fileDescriptor)
        val output = FileOutputStream(fd.fileDescriptor)
        val buf = ByteArray(32767)
        while (currentCoroutineContext().isActive) {
            val n = input.read(buf)
            if (n <= 0) { yield(); continue }
            val packet = buf.copyOf(n)
            cockpit.feed(packet)      // Lumra reads IP metadata only
            output.write(packet)      // pass through, unchanged
        }
    }

    // publishLoop writes the latest board to a file the UI polls. Runs on its own
    // cadence so rendering never blocks the packet path.
    private suspend fun publishLoop() {
        while (currentCoroutineContext().isActive) {
            val json = cockpit.boardJSON()
            runCatching {
                filesDir.resolve(BOARD_FILE).writeBytes(json)
            }
            delay(1000)
        }
    }

    override fun onDestroy() {
        scope?.cancel()
        tunnel?.close()
        tunnel = null
        super.onDestroy()
    }

    companion object {
        const val ACTION_STOP = "net.crode.lumra.STOP"
        const val BOARD_FILE = "board.json"
    }
}
