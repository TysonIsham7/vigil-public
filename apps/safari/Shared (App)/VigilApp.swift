import SwiftUI

@main
struct VigilApp: App {
    var body: some Scene {
        WindowGroup {
            ContentView()
        }
    }
}

struct ContentView: View {
    var body: some View {
        VStack(alignment: .leading, spacing: 12) {
            Text("Vigil")
                .font(.title)
            Text("Enable Vigil in Safari, then allow it on the websites you want checked. This container is a local build. It is not an App Store or TestFlight release.")
                .font(.body)
            Text("High Security Mode can talk to vigil serve at http://127.0.0.1:8787. On an iPhone, that address is the phone.")
                .font(.callout)
        }
        .padding(24)
        .frame(maxWidth: 480, alignment: .leading)
    }
}
