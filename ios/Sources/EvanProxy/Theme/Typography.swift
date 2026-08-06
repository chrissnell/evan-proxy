import SwiftUI
import CoreText

enum Typography {
    @MainActor private static var registered = false
    /// Register the bundled Inconsolata so `Font.custom` finds it from the SPM bundle.
    @MainActor static func registerFonts() {
        guard !registered,
              let url = Bundle.module.url(forResource: "Inconsolata-Regular", withExtension: "ttf") else { return }
        registered = true
        CTFontManagerRegisterFontsForURL(url as CFURL, .process, nil)
    }
    static func mono(_ size: CGFloat, weight: Font.Weight = .regular) -> Font {
        .custom("Inconsolata", size: size).weight(weight)
    }
}
