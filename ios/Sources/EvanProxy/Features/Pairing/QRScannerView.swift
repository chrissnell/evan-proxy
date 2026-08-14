import SwiftUI
import AVFoundation

/// Camera preview that reports the first QR code it sees, exactly once.
struct QRScannerView: UIViewControllerRepresentable {
    let onScan: (String) -> Void
    let onManualEntry: () -> Void

    func makeUIViewController(context: Context) -> ScannerViewController {
        let vc = ScannerViewController()
        vc.onScan = onScan
        vc.onManualEntry = onManualEntry
        return vc
    }
    func updateUIViewController(_ vc: ScannerViewController, context: Context) {}
}

/// Preflight for the scanner, decided before ANY AVFoundation permission call:
/// requesting camera access from a build whose Info.plist lost
/// NSCameraUsageDescription (a stale xcodegen generation — Generated/ is
/// gitignored) is an instant TCC crash, and the simulator has no camera to
/// scan with at all. Both must degrade to "enter the code manually", not crash
/// or show a silent black sheet.
enum ScannerGate: Equatable {
    case ready
    case missingUsageDescription
    case noCamera

    static func evaluate(usageDescription: String?, hasCamera: Bool) -> ScannerGate {
        let d = usageDescription?.trimmingCharacters(in: .whitespacesAndNewlines) ?? ""
        guard !d.isEmpty else { return .missingUsageDescription }
        return hasCamera ? .ready : .noCamera
    }
}

final class ScannerViewController: UIViewController, @preconcurrency AVCaptureMetadataOutputObjectsDelegate {
    var onScan: ((String) -> Void)?
    var onManualEntry: (() -> Void)?
    private let session = AVCaptureSession()
    private var previewLayer: AVCaptureVideoPreviewLayer?
    private var scanned = false

    override func viewDidLoad() {
        super.viewDidLoad()
        view.backgroundColor = .black
        let gate = ScannerGate.evaluate(
            usageDescription: Bundle.main.object(forInfoDictionaryKey: "NSCameraUsageDescription") as? String,
            hasCamera: AVCaptureDevice.default(for: .video) != nil)
        switch gate {
        case .missingUsageDescription:
            showMessage("This build can't use the camera — enter the code manually instead. (Developers: the Xcode project is stale; run xcodegen generate in ios/App and rebuild.)")
            return
        case .noCamera:
            showMessage("No camera on this device — enter the code manually instead")
            return
        case .ready:
            break
        }
        switch AVCaptureDevice.authorizationStatus(for: .video) {
        case .authorized:
            configureSession()
        case .notDetermined:
            AVCaptureDevice.requestAccess(for: .video) { granted in
                DispatchQueue.main.async { [weak self] in
                    if granted { self?.configureSession() } else { self?.showDenied() }
                }
            }
        default:
            showDenied()
        }
    }

    private func configureSession() {
        guard let device = AVCaptureDevice.default(for: .video),
              let input = try? AVCaptureDeviceInput(device: device),
              session.canAddInput(input) else { return }
        session.addInput(input)
        let output = AVCaptureMetadataOutput()
        guard session.canAddOutput(output) else { return }
        session.addOutput(output)
        // Deliver callbacks on main so the @MainActor-isolated delegate is safe.
        output.setMetadataObjectsDelegate(self, queue: .main)
        output.metadataObjectTypes = [.qr]
        let preview = AVCaptureVideoPreviewLayer(session: session)
        preview.videoGravity = .resizeAspectFill
        preview.frame = view.bounds
        view.layer.addSublayer(preview)
        previewLayer = preview
        // startRunning blocks briefly; acceptable for a short-lived pairing modal
        // and keeps the non-Sendable session on the main actor under Swift 6.
        session.startRunning()
    }

    private func showDenied() {
        showMessage("Camera access denied — enable it in Settings to scan, or enter the code manually")
    }

    private func showMessage(_ text: String) {
        let label = UILabel()
        label.text = text
        label.numberOfLines = 0
        label.textAlignment = .center
        label.textColor = .white
        label.font = .monospacedSystemFont(ofSize: 14, weight: .regular)

        var config = UIButton.Configuration.bordered()
        config.attributedTitle = AttributedString(
            "Enter Code Manually",
            attributes: AttributeContainer([.font: UIFont.monospacedSystemFont(ofSize: 14, weight: .semibold)]))
        let button = UIButton(configuration: config, primaryAction: UIAction { [weak self] _ in
            self?.onManualEntry?()
        })
        button.tintColor = .white

        let stack = UIStackView(arrangedSubviews: [label, button])
        stack.axis = .vertical
        stack.spacing = 16
        stack.alignment = .center
        stack.translatesAutoresizingMaskIntoConstraints = false
        view.addSubview(stack)
        NSLayoutConstraint.activate([
            stack.centerXAnchor.constraint(equalTo: view.centerXAnchor),
            stack.centerYAnchor.constraint(equalTo: view.centerYAnchor),
            stack.leadingAnchor.constraint(greaterThanOrEqualTo: view.leadingAnchor, constant: 20),
            stack.trailingAnchor.constraint(lessThanOrEqualTo: view.trailingAnchor, constant: -20),
        ])
    }

    override func viewDidLayoutSubviews() {
        super.viewDidLayoutSubviews()
        previewLayer?.frame = view.bounds
    }

    override func viewWillDisappear(_ animated: Bool) {
        super.viewWillDisappear(animated)
        if session.isRunning { session.stopRunning() }
    }

    func metadataOutput(_ output: AVCaptureMetadataOutput,
                        didOutput metadataObjects: [AVMetadataObject],
                        from connection: AVCaptureConnection) {
        guard !scanned,
              let obj = metadataObjects.first as? AVMetadataMachineReadableCodeObject,
              obj.type == .qr, let value = obj.stringValue else { return }
        scanned = true
        session.stopRunning()
        onScan?(value)
    }
}
