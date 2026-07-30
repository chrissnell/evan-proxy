import SwiftUI
import CoreText

enum Typography {
    /// Register the bundled Inconsolata so `Font.custom` finds it from the SPM bundle.
    static func registerFonts() {
        guard let url = Bundle.module.url(forResource: "Inconsolata-Regular", withExtension: "ttf") else { return }
        CTFontManagerRegisterFontsForURL(url as CFURL, .process, nil)
    }
    static func mono(_ size: CGFloat, weight: Font.Weight = .regular) -> Font {
        .custom("Inconsolata", size: size).weight(weight)
    }
}
