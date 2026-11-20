// swift-tools-version: 6.3

//===----------------------------------------------------------------------===//
//
// This source file is part of the bgpls project.
//
// Copyright (c) 2026 Craig A. Munro
//
// Licensed under the Apache License, Version 2.0.
// See the LICENSE file for details.
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

import PackageDescription

let package = Package(
    name: "bgpls",
    platforms: [
        .iOS(.v18),
        .macOS(.v15),
    ],
    products: [
        .library(name: "BGPLSClient", targets: ["BGPLSClient"]),
        .executable(name: "bgpls", targets: ["BGPLSExecutable"]),
    ],
    dependencies: [
        .package(
            url: "https://github.com/RouteObjects/swift-cidr.git",
            .upToNextMinor(from: "0.11.0")
        ),
        .package(
            url: "https://github.com/apple/swift-nio.git",
            .upToNextMajor(from: "2.104.0")
        ),
        .package(
            url: "https://github.com/apple/swift-nio-extras.git",
            .upToNextMajor(from: "1.24.0")
        ),
        .package(
            url: "https://github.com/apple/swift-argument-parser",
            .upToNextMajor(from: "1.7.0")
        ),
        .package(
            url: "https://github.com/swift-server/swift-service-lifecycle.git",
            .upToNextMajor(from: "2.12.0")
        ),
    ],
    targets: [
        .target(
            name: "BGPLSClient",
            dependencies: [
                .product(name: "CIDR", package: "swift-cidr"),
                .product(name: "CIDRNIO", package: "swift-cidr"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "NIOExtras", package: "swift-nio-extras"),
            ]
        ),
        // Keep command behavior importable for SwiftPM and Xcode tests.
        .target(
            name: "BGPLSCLI",
            dependencies: [
                "BGPLSClient",
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "CIDR", package: "swift-cidr"),
                .product(name: "CIDRArgumentParser", package: "swift-cidr"),
                // Signal handling belongs to the CLI boundary, not BGPLSClient.
                .product(name: "UnixSignals", package: "swift-service-lifecycle"),
            ]
        ),
        .executableTarget(
            name: "BGPLSExecutable",
            dependencies: ["BGPLSCLI"]
        ),
        .testTarget(
            name: "BGPLSClientTests",
            dependencies: [
                "BGPLSClient",
                .product(name: "CIDR", package: "swift-cidr"),
                .product(name: "CIDRNIO", package: "swift-cidr"),
                .product(name: "NIOEmbedded", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
            ]
        ),
        .testTarget(
            name: "BGPLSCLITests",
            dependencies: [
                "BGPLSCLI",
                "BGPLSClient",
                .product(name: "CIDR", package: "swift-cidr"),
                .product(name: "CIDRArgumentParser", package: "swift-cidr"),
                .product(name: "ArgumentParser", package: "swift-argument-parser"),
                .product(name: "NIOCore", package: "swift-nio"),
                .product(name: "NIOPosix", package: "swift-nio"),
                .product(name: "UnixSignals", package: "swift-service-lifecycle"),
            ]
        ),
    ],
    swiftLanguageModes: [.v6]
)
