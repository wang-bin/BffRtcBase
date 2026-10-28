// swift-tools-version: 5.9
import PackageDescription

let package = Package(
    name: "JsppRTCBase",
    platforms: [
        .iOS(.v13),
    ],
    products: [
        .library(
            name: "JsppRTCBase",
            type: .static,
            targets: ["JsppRTCBase"]
        ),
    ],
    dependencies: [
        .package(
            url: "https://code.jspp.com/laser/quic.git",
            branch: "main"
        ),
        .package(url: "https://code.jspp.com/wangbin/webrtc-7871-ios.git", branch: "master"),
    ],
    targets: [
        .target(
            name: "JsppRTCBase",
            dependencies: [
                .product(name: "JsppRTCQuic", package: "quic"),
                .product(name: "curl", package: "webrtc-7871-ios"),
                .product(name: "openssl", package: "webrtc-7871-ios"),
            ],
            path: ".",
            exclude: [
                ".gitmodules",
                "CMakeLists.txt",
                "JMI",
                "TODO.md",
                "quic",
                "run_PbCJson_test.sh",
                "xcfwk.cmake",
            ],
            sources: [
                "Cert.cpp",
                "DateTime.cpp",
                "FileLogger.cpp",
                "HttpClient.cpp",
                "Log.cpp",
                "NodeSelector.cpp",
                "PbCJson.cpp",
                "PbCJson_test.cpp",
                "QuicSocket.cpp",
                "Signal.cpp",
                "SignalChannel.cpp",
                "SniUrl.cpp",
                "WebSocket.cpp",
                "laser-ca.der.c",
                "protobuf-c/protobuf-c.c",
                "rtc.pb-c.c",
                "stun_test.cpp",
            ],
            publicHeadersPath: "include",
            cSettings: [
                .define("JSON_NOEXCEPTION"),
                .headerSearchPath("."),
                .headerSearchPath("protobuf-c"),
            ],
            cxxSettings: [
                .define("JSON_NOEXCEPTION"),
                .headerSearchPath("."),
                .headerSearchPath("protobuf-c"),
                .unsafeFlags(["-fno-rtti"]),
            ],
            linkerSettings: [
                .linkedFramework("Network"),
                .linkedFramework("Security"),
                .linkedLibrary("z"),
            ]
        ),
    ],
    cLanguageStandard: .gnu17,
    cxxLanguageStandard: .gnucxx2b
)
