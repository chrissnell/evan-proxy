import SwiftUI

struct LoginView: View {
    @State var model: LoginModel
    var pairing: PairingModel? = nil
    @State private var showScanner = false
    var body: some View {
        VStack(spacing: 16) {
            Text("evan-proxy").font(Typography.mono(22, weight: .bold)).foregroundStyle(Palette.fg)
            Box {
                VStack(alignment: .leading, spacing: 8) {
                    if let e = model.error { Text(e).font(Typography.mono(12)).foregroundStyle(Palette.danger) }
                    Text("username").font(Typography.mono(12)).foregroundStyle(Palette.fgMuted)
                    TextField("", text: $model.username).textInputAutocapitalization(.never)
                        .autocorrectionDisabled().font(Typography.mono(14))
                        .padding(8).overlay(RoundedRectangle(cornerRadius: 2).stroke(Palette.border))
                    Text("password").font(Typography.mono(12)).foregroundStyle(Palette.fgMuted)
                    SecureField("", text: $model.password).font(Typography.mono(14))
                        .padding(8).overlay(RoundedRectangle(cornerRadius: 2).stroke(Palette.border))
                    PillButton(title: model.busy ? "…" : "login", color: Palette.fg) {
                        Task { await model.submit() }
                    }.padding(.top, 8)
                }
            }
            if let pairing {
                Box {
                    VStack(alignment: .leading, spacing: 8) {
                        Text("or add this device without a password —\nscan the QR from the admin \"devices\" panel")
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
        }
        .padding(20).frame(maxHeight: .infinity)
        .background(Palette.bg).foregroundStyle(Palette.fg)
        .sheet(isPresented: $showScanner) {
            if let pairing {
                QRScannerView { code in
                    showScanner = false
                    Task { await pairing.handle(scanned: code) }
                }
                .ignoresSafeArea()
            }
        }
    }
}
