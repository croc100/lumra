// MainActivity — the standalone monitoring UI (host mode B). It requests VPN
// consent, starts/stops LumraVpnService, and renders the live board the service
// publishes. Diagnosis only: it shows who is blocking/watching/down, never
// reroutes.

package net.crode.lumra

import android.content.Intent
import android.net.VpnService
import android.os.Bundle
import androidx.activity.ComponentActivity
import androidx.activity.compose.setContent
import androidx.activity.result.contract.ActivityResultContracts
import androidx.compose.foundation.layout.*
import androidx.compose.foundation.lazy.LazyColumn
import androidx.compose.foundation.lazy.items
import androidx.compose.material3.*
import androidx.compose.runtime.*
import androidx.compose.ui.Modifier
import androidx.compose.ui.graphics.Color
import androidx.compose.ui.unit.dp
import kotlinx.coroutines.delay
import org.json.JSONArray

class MainActivity : ComponentActivity() {
    private val prepareVpn = registerForActivityResult(ActivityResultContracts.StartActivityForResult()) {
        if (it.resultCode == RESULT_OK) startService(serviceIntent(null))
    }

    override fun onCreate(savedInstanceState: Bundle?) {
        super.onCreate(savedInstanceState)
        setContent { MaterialTheme { BoardScreen(onStart = ::startVpn, onStop = ::stopVpn) } }
    }

    private fun startVpn() {
        val consent = VpnService.prepare(this)
        if (consent != null) prepareVpn.launch(consent) else startService(serviceIntent(null))
    }

    private fun stopVpn() = startService(serviceIntent(LumraVpnService.ACTION_STOP))

    private fun serviceIntent(action: String?) =
        Intent(this, LumraVpnService::class.java).apply { this.action = action }
}

data class BoardRow(
    val domain: String, val nature: String, val badge: String,
    val tls: String, val status: String,
    val who: String?, val why: String?,
)

@Composable
fun BoardScreen(onStart: () -> Unit, onStop: () -> Unit) {
    val context = androidx.compose.ui.platform.LocalContext.current
    var rows by remember { mutableStateOf(emptyList<BoardRow>()) }
    var running by remember { mutableStateOf(false) }

    LaunchedEffect(Unit) {
        while (true) {
            rows = readBoard(context.filesDir.resolve(LumraVpnService.BOARD_FILE))
            delay(1000)
        }
    }

    Scaffold(topBar = {
        TopAppBar(
            title = { Text("Lumra — ${rows.size} domains") },
            actions = {
                TextButton(onClick = { running = !running; if (running) onStart() else onStop() }) {
                    Text(if (running) "Stop" else "Start")
                }
            },
        )
    }) { padding ->
        LazyColumn(Modifier.padding(padding)) {
            items(rows) { row ->
                Column(
                    Modifier
                        .fillMaxWidth()
                        .background(natureColor(row.nature))
                        .padding(12.dp)
                ) {
                    Row {
                        Text("${row.badge} ")
                        Text(row.domain, style = MaterialTheme.typography.titleMedium)
                        Spacer(Modifier.weight(1f))
                        Text(row.tls, style = MaterialTheme.typography.labelSmall)
                    }
                    Text(row.status, style = MaterialTheme.typography.bodyMedium)
                    row.who?.let { Text("who: $it", style = MaterialTheme.typography.labelSmall) }
                    row.why?.let { Text("why: $it", style = MaterialTheme.typography.labelSmall) }
                }
            }
        }
    }
}

private fun natureColor(nature: String): Color = when (nature) {
    "control" -> Color(0x1FE53935)
    "surveillance" -> Color(0x1F8E24AA)
    "degradation" -> Color(0x1FFB8C00)
    "fault" -> Color(0x1FFDD835)
    else -> Color.Transparent
}

// readBoard parses the JSON the service publishes (internal/live.Row shape).
private fun readBoard(file: java.io.File): List<BoardRow> {
    if (!file.exists()) return emptyList()
    return runCatching {
        val arr = JSONArray(file.readText())
        (0 until arr.length()).map { i ->
            val o = arr.getJSONObject(i)
            BoardRow(
                domain = o.optString("domain"),
                nature = o.optString("nature"),
                badge = o.optString("badge"),
                tls = o.optString("tls"),
                status = o.optString("status"),
                who = o.optString("who").ifEmpty { null },
                why = o.optString("why").ifEmpty { null },
            )
        }
    }.getOrDefault(emptyList())
}
