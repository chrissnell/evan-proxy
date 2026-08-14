import SwiftUI

/// The only way into the app: scan the pairing QR from the admin "devices"
/// panel (or open its evanproxy:// link, or type the code by hand).
/// No password entry on the device.
struct PairingView: View {
    let pairing: PairingModel
    @State private var showScanner = false
    @State private var showManual = false
    @State private var staged: PendingPair?

    var body: some View {
        VStack(spacing: 16) {
            Text("evan-proxy").font(Typography.mono(22, weight: .bold)).foregroundStyle(Palette.fg)
            Box {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Pair this device —\nScan the QR from the admin \"Devices\" panel")
                        .font(Typography.mono(12)).foregroundStyle(Palette.fgMuted)
                    if let e = pairing.error {
                        Text(e).font(Typography.mono(12)).foregroundStyle(Palette.danger)
                    }
                    PillButton(title: pairing.busy ? "…" : "Scan QR to Pair", color: Palette.accent) {
                        showScanner = true
                    }
                    PillButton(title: "Enter Code Manually") { showManual = true }
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
        // Staging waits for onDismiss: setting `pending` while the sheet is
        // still up would trigger RootView's confirmation alert mid-dismissal,
        // which SwiftUI can drop.
        .sheet(isPresented: $showManual, onDismiss: {
            if let p = staged { staged = nil; pairing.stage(p) }
        }) {
            ManualPairSheet { p in
                staged = p
                showManual = false
            }
        }
    }
}

/// Camera-free fallback: type the server address and the enrollment code
/// shown under the QR in the admin "Devices" panel. Validation errors stay
/// local to the sheet so they never bleed onto the scan screen (or vice versa).
struct ManualPairSheet: View {
    let onSubmit: (PendingPair) -> Void
    @State private var host = ""
    @State private var code = ""
    @State private var error: String?

    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            SectionHeader(title: "enter pairing code")
            Box {
                VStack(alignment: .leading, spacing: 8) {
                    Text("Server").font(Typography.mono(12)).foregroundStyle(Palette.fgMuted)
                    TextField("proxy.example.com", text: $host)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .keyboardType(.URL)
                        .font(Typography.mono(14)).padding(8)
                        .overlay(RoundedRectangle(cornerRadius: 2).stroke(Palette.border))
                    Text("Code").font(Typography.mono(12)).foregroundStyle(Palette.fgMuted)
                    TextField("", text: $code)
                        .textInputAutocapitalization(.never).autocorrectionDisabled()
                        .font(Typography.mono(14)).padding(8)
                        .overlay(RoundedRectangle(cornerRadius: 2).stroke(Palette.border))
                    Text("The code is shown under the QR in the admin \"Devices\" panel")
                        .font(Typography.mono(11)).foregroundStyle(Palette.fgDim)
                    if let e = error {
                        Text(e).font(Typography.mono(12)).foregroundStyle(Palette.danger)
                    }
                }
            }
            PillButton(title: "Pair", color: Palette.accent, filled: true) {
                guard let p = PairingModel.validateManual(host: host, code: code) else {
                    error = "Invalid server address or code"
                    return
                }
                onSubmit(p)
            }
        }
        .padding(16).frame(maxHeight: .infinity, alignment: .top)
        .background(Palette.bg)
        .presentationDetents([.height(360)])
    }
}
