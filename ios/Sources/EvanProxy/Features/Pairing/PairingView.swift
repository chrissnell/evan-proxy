import SwiftUI

/// The only way into the app: scan the pairing QR from the admin "devices"
/// panel (or open its evanproxy:// link). No password entry on the device.
struct PairingView: View {
    let pairing: PairingModel
    @State private var showScanner = false

    var body: some View {
        VStack(spacing: 16) {
            Text("evan-proxy").font(Typography.mono(22, weight: .bold)).foregroundStyle(Palette.fg)
            Box {
                VStack(alignment: .leading, spacing: 8) {
                    Text("pair this device —\nscan the QR from the admin \"devices\" panel")
                        .font(Typography.mono(12)).foregroundStyle(Palette.fgMuted)
                    if let e = pairing.error {
                        Text(e).font(Typography.mono(12)).foregroundStyle(Palette.danger)
                    }
                    PillButton(title: pairing.busy ? "…" : "scan qr to pair", color: Palette.accent) {
                        showScanner = true
                    }
                }
            }
        }
        .padding(20).frame(maxHeight: .infinity)
        .background(Palette.bg).foregroundStyle(Palette.fg)
        .sheet(isPresented: $showScanner) {
            QRScannerView { code in
                showScanner = false
                Task { await pairing.handle(scanned: code) }
            }
            .ignoresSafeArea()
        }
    }
}
