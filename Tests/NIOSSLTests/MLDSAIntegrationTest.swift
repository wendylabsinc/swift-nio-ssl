//===----------------------------------------------------------------------===//
//
// This source file is part of the SwiftNIO open source project
//
// Copyright (c) 2026 Apple Inc. and the SwiftNIO project authors
// Licensed under Apache License v2.0
//
// See LICENSE.txt for license information
// See CONTRIBUTORS.txt for the list of SwiftNIO project authors
//
// SPDX-License-Identifier: Apache-2.0
//
//===----------------------------------------------------------------------===//

@_implementationOnly import CNIOBoringSSL
import NIOConcurrencyHelpers
import NIOCore
import NIOEmbedded
import XCTest

@testable import NIOSSL

/// Generates a fresh ML-DSA-65 (FIPS 204) key as an `EVP_PKEY`.
///
/// The key is derived from a random 32-byte seed via BoringSSL's EVP ML-DSA
/// integration, the same key type used for ML-DSA X.509 certificates and TLS
/// signatures.
private func generateMLDSA65PrivateKey() -> OpaquePointer {
    var seed = [UInt8](repeating: 0, count: Int(MLDSA_SEED_BYTES))
    let rc = seed.withUnsafeMutableBufferPointer { RAND_bytes($0.baseAddress, $0.count) }
    precondition(rc == 1, "Failed to generate ML-DSA seed")
    let pkey = seed.withUnsafeBufferPointer { seedPtr in
        EVP_PKEY_from_private_seed(
            EVP_pkey_ml_dsa_65(),
            seedPtr.baseAddress,
            seedPtr.count
        )
    }
    precondition(pkey != nil, "Failed to derive ML-DSA-65 key from seed")
    return pkey!
}

/// Builds an `X509_NAME` containing a single common name entry.
private func makeName(commonName: String) -> OpaquePointer {
    let name = X509_NAME_new()!
    commonName.withCString { (pointer: UnsafePointer<Int8>) -> Void in
        pointer.withMemoryRebound(to: UInt8.self, capacity: commonName.utf8.count) {
            (pointer: UnsafePointer<UInt8>) -> Void in
            X509_NAME_add_entry_by_NID(
                name,
                NID_commonName,
                MBSTRING_UTF8,
                UnsafeMutablePointer(mutating: pointer),
                ossl_ssize_t(commonName.utf8.count),
                -1,
                0
            )
        }
    }
    return name
}

/// Issues an X.509 certificate for `subjectKey`, signed by `issuerKey`.
///
/// `issuerDigest` must be `nil` for an ML-DSA issuer (ML-DSA is not a
/// hash-then-sign scheme) and a digest such as `EVP_sha256()` for a classical
/// issuer key.
private func issueCertificate(
    subjectCommonName: String,
    subjectKey: OpaquePointer,
    issuerCommonName: String,
    issuerKey: OpaquePointer,
    issuerDigest: OpaquePointer?,
    isCertificateAuthority: Bool,
    extendedKeyUsage: String?
) -> NIOSSLCertificate {
    let x = X509_new()!
    X509_set_version(x, 2)

    var serial = randomSerialNumber()
    X509_set_serialNumber(x, &serial)

    let notBefore = ASN1_TIME_new()!
    var now = time(nil)
    ASN1_TIME_set(notBefore, now)
    X509_set_notBefore(x, notBefore)
    ASN1_TIME_free(notBefore)

    now += 60 * 60  // Give ourselves an hour.
    let notAfter = ASN1_TIME_new()!
    ASN1_TIME_set(notAfter, now)
    X509_set_notAfter(x, notAfter)
    ASN1_TIME_free(notAfter)

    X509_set_pubkey(x, subjectKey)

    let subjectName = makeName(commonName: subjectCommonName)
    X509_set_subject_name(x, subjectName)
    X509_NAME_free(subjectName)

    let issuerName = makeName(commonName: issuerCommonName)
    X509_set_issuer_name(x, issuerName)
    X509_NAME_free(issuerName)

    if isCertificateAuthority {
        addExtension(x509: x, nid: NID_basic_constraints, value: "critical,CA:TRUE")
    } else {
        addExtension(x509: x, nid: NID_basic_constraints, value: "critical,CA:FALSE")
        addExtension(x509: x, nid: NID_subject_alt_name, value: "DNS:localhost")
    }
    addExtension(x509: x, nid: NID_subject_key_identifier, value: "hash")
    if let extendedKeyUsage = extendedKeyUsage {
        addExtension(x509: x, nid: NID_ext_key_usage, value: "critical,\(extendedKeyUsage)")
    }

    let signRC = X509_sign(x, issuerKey, issuerDigest)
    precondition(signRC != 0, "Failed to sign certificate for \(subjectCommonName)")

    return NIOSSLCertificate.fromUnsafePointer(takingOwnership: x)
}

/// A complete test PKI: a self-signed root, an intermediate, and server and
/// client leaves signed by the intermediate.
private struct TestPKI {
    var root: NIOSSLCertificate
    var intermediate: NIOSSLCertificate
    var serverLeaf: NIOSSLCertificate
    var serverKey: OpaquePointer
    var clientLeaf: NIOSSLCertificate
    var clientKey: OpaquePointer

    /// Builds a PKI whose CAs are ML-DSA-65. `classicalClientLeaf` selects a
    /// classical P-256 client leaf (signed by the ML-DSA intermediate) to
    /// exercise the mixed-algorithm transitional chain.
    init(prefix: String, classicalClientLeaf: Bool = false) {
        let rootKey = generateMLDSA65PrivateKey()
        let intermediateKey = generateMLDSA65PrivateKey()
        self.serverKey = generateMLDSA65PrivateKey()
        self.clientKey = classicalClientLeaf ? generateECPrivateKey() : generateMLDSA65PrivateKey()

        // ML-DSA issuers sign with a nil digest.
        self.root = issueCertificate(
            subjectCommonName: "\(prefix) ML-DSA Root CA",
            subjectKey: rootKey,
            issuerCommonName: "\(prefix) ML-DSA Root CA",
            issuerKey: rootKey,
            issuerDigest: nil,
            isCertificateAuthority: true,
            extendedKeyUsage: nil
        )
        self.intermediate = issueCertificate(
            subjectCommonName: "\(prefix) ML-DSA Intermediate CA",
            subjectKey: intermediateKey,
            issuerCommonName: "\(prefix) ML-DSA Root CA",
            issuerKey: rootKey,
            issuerDigest: nil,
            isCertificateAuthority: true,
            extendedKeyUsage: nil
        )
        self.serverLeaf = issueCertificate(
            subjectCommonName: "localhost",
            subjectKey: self.serverKey,
            issuerCommonName: "\(prefix) ML-DSA Intermediate CA",
            issuerKey: intermediateKey,
            issuerDigest: nil,
            isCertificateAuthority: false,
            extendedKeyUsage: "serverAuth"
        )
        self.clientLeaf = issueCertificate(
            subjectCommonName: "\(prefix) client",
            subjectKey: self.clientKey,
            issuerCommonName: "\(prefix) ML-DSA Intermediate CA",
            issuerKey: intermediateKey,
            issuerDigest: nil,
            isCertificateAuthority: false,
            extendedKeyUsage: "clientAuth"
        )

        EVP_PKEY_free(rootKey)
        EVP_PKEY_free(intermediateKey)
    }
}

final class MLDSAIntegrationTest: XCTestCase {
    private func serverConfiguration(pki: TestPKI, trustRoot: NIOSSLCertificate) throws -> NIOSSLContext {
        var config = TLSConfiguration.makeServerConfiguration(
            certificateChain: [.certificate(pki.serverLeaf), .certificate(pki.intermediate)],
            privateKey: .privateKey(NIOSSLPrivateKey.fromUnsafePointer(takingOwnership: pki.serverKey))
        )
        config.certificateVerification = .noHostnameVerification
        config.trustRoots = .certificates([trustRoot])
        // BoringSSL's default advertised (verify) signature-algorithm list does
        // not include ML-DSA, so the peer would never offer to verify an ML-DSA
        // signature. Opt in explicitly. See the note on `mldsaSignatureAlgorithms`.
        config.verifySignatureAlgorithms = Self.mldsaSignatureAlgorithms
        return try NIOSSLContext(configuration: config)
    }

    private func clientConfiguration(pki: TestPKI, trustRoot: NIOSSLCertificate) throws -> NIOSSLContext {
        var config = TLSConfiguration.makeClientConfiguration()
        config.certificateVerification = .noHostnameVerification
        config.trustRoots = .certificates([trustRoot])
        config.certificateChain = [.certificate(pki.clientLeaf), .certificate(pki.intermediate)]
        config.privateKey = .privateKey(NIOSSLPrivateKey.fromUnsafePointer(takingOwnership: pki.clientKey))
        config.verifySignatureAlgorithms = Self.mldsaSignatureAlgorithms
        return try NIOSSLContext(configuration: config)
    }

    /// ML-DSA-65 plus the classical algorithms needed for the mixed P-256 leaf
    /// case. Both peers must advertise these so each side is willing to verify
    /// the other's certificate-verify signature.
    private static let mldsaSignatureAlgorithms: [SignatureAlgorithm] = [
        .mldsa65,
        .ecdsaSecp256R1Sha256,
        .rsaPssRsaeSha256,
        .ed25519,
    ]

    /// Full ML-DSA-65 chain on both ends: root -> intermediate -> leaf, with the
    /// client presenting a leaf chain that must validate to the pinned root.
    func testMLDSA65MutualTLSHandshakeSucceeds() throws {
        let pki = TestPKI(prefix: "Trusted")
        let serverContext = try self.serverConfiguration(pki: pki, trustRoot: pki.root)
        let clientContext = try self.clientConfiguration(pki: pki, trustRoot: pki.root)

        let b2b = BackToBackEmbeddedChannel()
        let clientHandshake = HandshakeCompletedHandler()
        let serverHandshake = HandshakeCompletedHandler()
        try b2b.client.pipeline.syncOperations.addHandlers([
            try NIOSSLClientHandler(context: clientContext, serverHostname: "localhost"),
            clientHandshake,
        ])
        try b2b.server.pipeline.syncOperations.addHandlers([
            NIOSSLServerHandler(context: serverContext),
            serverHandshake,
        ])

        XCTAssertNoThrow(try b2b.connectInMemory())
        XCTAssertTrue(clientHandshake.handshakeSucceeded)
        XCTAssertTrue(serverHandshake.handshakeSucceeded)
    }

    /// A client whose chain is signed by a different (untrusted) ML-DSA root must
    /// be rejected by the server.
    func testMLDSA65ClientWithUntrustedRootIsRejected() throws {
        let trustedPKI = TestPKI(prefix: "Trusted")
        let attackerPKI = TestPKI(prefix: "Attacker")

        // Server trusts only the trusted root, but presents its own trusted leaf.
        let serverContext = try self.serverConfiguration(pki: trustedPKI, trustRoot: trustedPKI.root)
        // Client presents the attacker chain, and trusts the attacker root so that
        // it is the *server* that rejects the peer, isolating client-cert rejection.
        let clientContext = try self.clientConfiguration(pki: attackerPKI, trustRoot: attackerPKI.root)

        let b2b = BackToBackEmbeddedChannel()
        try b2b.client.pipeline.syncOperations.addHandlers([
            try NIOSSLClientHandler(context: clientContext, serverHostname: "localhost")
        ])
        try b2b.server.pipeline.syncOperations.addHandlers([
            NIOSSLServerHandler(context: serverContext)
        ])

        // Both peers advertise ML-DSA in their verify list, so signature-algorithm
        // negotiation succeeds and the handshake fails specifically because the
        // server cannot build a trusted chain for the attacker's client leaf
        // (BoringSSL: CERTIFICATE_VERIFY_FAILED).
        XCTAssertThrowsError(try b2b.connectInMemory()) { error in
            switch error as? NIOSSLError {
            case .some(.handshakeFailed):
                break  // Expected: the server rejected the untrusted client chain.
            default:
                XCTFail("Unexpected error: \(error)")
            }
        }
    }

    /// After a successful ML-DSA handshake the server can read the peer's
    /// certificate chain via the verification callback.
    func testMLDSA65ServerReadsPeerCertificate() throws {
        let pki = TestPKI(prefix: "Trusted")
        let serverContext = try self.serverConfiguration(pki: pki, trustRoot: pki.root)
        let clientContext = try self.clientConfiguration(pki: pki, trustRoot: pki.root)

        let peerChain = NIOLockedValueBox<[NIOSSLCertificate]>([])
        let serverHandler = NIOSSLServerHandler(
            context: serverContext,
            customVerificationCallback: { certificates, promise in
                peerChain.withLockedValue { $0 = certificates }
                promise.succeed(.certificateVerified)
            }
        )

        let b2b = BackToBackEmbeddedChannel()
        let serverHandshake = HandshakeCompletedHandler()
        try b2b.client.pipeline.syncOperations.addHandlers([
            try NIOSSLClientHandler(context: clientContext, serverHostname: "localhost")
        ])
        try b2b.server.pipeline.syncOperations.addHandlers([serverHandler, serverHandshake])

        XCTAssertNoThrow(try b2b.connectInMemory())
        XCTAssertTrue(serverHandshake.handshakeSucceeded)

        let chain = peerChain.withLockedValue { $0 }
        XCTAssertEqual(chain.first, pki.clientLeaf, "Server should see the client's ML-DSA leaf certificate")
        XCTAssertTrue(chain.contains(pki.intermediate), "Server should see the presented intermediate")
    }

    /// Transitional mixed chain: a classical P-256 client leaf signed by an
    /// ML-DSA-65 intermediate, itself signed by an ML-DSA-65 root.
    func testMixedP256LeafUnderMLDSAIntermediate() throws {
        let pki = TestPKI(prefix: "Mixed", classicalClientLeaf: true)
        let serverContext = try self.serverConfiguration(pki: pki, trustRoot: pki.root)
        let clientContext = try self.clientConfiguration(pki: pki, trustRoot: pki.root)

        let b2b = BackToBackEmbeddedChannel()
        let clientHandshake = HandshakeCompletedHandler()
        let serverHandshake = HandshakeCompletedHandler()
        try b2b.client.pipeline.syncOperations.addHandlers([
            try NIOSSLClientHandler(context: clientContext, serverHostname: "localhost"),
            clientHandshake,
        ])
        try b2b.server.pipeline.syncOperations.addHandlers([
            NIOSSLServerHandler(context: serverContext),
            serverHandshake,
        ])

        XCTAssertNoThrow(try b2b.connectInMemory())
        XCTAssertTrue(clientHandshake.handshakeSucceeded)
        XCTAssertTrue(serverHandshake.handshakeSucceeded)
    }
}
