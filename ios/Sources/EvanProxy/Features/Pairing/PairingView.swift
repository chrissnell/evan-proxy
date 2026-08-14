import SwiftUI

/// The only way into the app: scan the pairing QR from the admin "devices"
/// panel (or open its evanproxy:// link, or type the code by hand).
/// No password entry on the device.
struct PairingView: View {
    let pairing: PairingModel
    @State private var showScanner = false
    @State private var showManual = false

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
                    PillButton(title: "Enter Code Manually") {
                        pairing.error = nil
                        showManual = true
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
        .sheet(isPresented: $showManual) {
            ManualPairSheet(pairing: pairing)
        }
    }
}

/// Camera-free fallback: type the server address and the enrollment code
/// shown under the QR in the admin "Devices" panel.
struct ManualPairSheet: View {
    let pairing: PairingModel
    @Environment(\.dismiss) private var dismiss
    @State private var host = ""
    @State private var code = ""

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
                    if let e = pairing.error {
                        Text(e).font(Typography.mono(12)).foregroundStyle(Palette.danger)
                    }
                }
            }
            PillButton(title: "Pair", color: Palette.accent, filled: true) {
                pairing.handleManual(host: host, code: code)
                // Success stages a pending pair; the confirmation alert takes
                // over once the sheet is gone. Failure keeps the sheet up with
                // the error inline so the typo can be fixed in place.
                if pairing.pending != nil { dismiss() }
            }
        }
        .padding(16).frame(maxHeight: .infinity, alignment: .top)
        .background(Palette.bg)
        .presentationDetents([.height(360)])
    }
}
