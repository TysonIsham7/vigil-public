import Foundation
import SafariServices

class SafariWebExtensionHandler: NSObject, NSExtensionRequestHandling {
    func beginRequest(with context: NSExtensionContext) {
        let message = Self.incoming(context)
        Task {
            let payload = await NativeCertCheck.respond(to: message)
            let item = NSExtensionItem()
            item.userInfo = [SFExtensionMessageKey: payload]
            context.completeRequest(returningItems: [item], completionHandler: nil)
        }
    }

    /// Reads the extension message and does not copy it into the reply.
    private static func incoming(_ context: NSExtensionContext) -> Any? {
        let item = context.inputItems.first as? NSExtensionItem
        return item?.userInfo?[SFExtensionMessageKey]
    }
}
