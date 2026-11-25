import Foundation
import NetworkExtension

// System extension entry point: hand control to the Network Extension framework,
// which instantiates FilterDataProvider (named in Info.plist NEProviderClasses).
autoreleasepool {
    NEProvider.startSystemExtensionMode()
}
dispatchMain()
