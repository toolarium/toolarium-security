# toolarium-security

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [ 1.1.6 ] - 2026-05-11
### Changed
- Updated dependencies: toolarium-common 1.0.0, BouncyCastle 1.80.
- SSLContextFactory uses TLSv1.2 instead of generic TLS to prevent TLS 1.0/1.1 negotiation.
- SSLServerSocket restricted to TLSv1.2/TLSv1.3 protocols only.
- CertificateGenerator uses SecureRandom for certificate serial numbers instead of System.currentTimeMillis().
- CertificateGenerator sets BasicConstraints CA=true only for root certificates, end-entity certificates get CA=false.
- CertificateGenerator assigns appropriate KeyUsage per certificate type (CA vs end-entity).
- CertificateGenerator SAN extension merges user-provided DN and localhost into a single extension.
- CertificateGenerator EC signature algorithm corrected to SHA256withECDSA.
- CertificateGenerator main method now takes password and other parameters as arguments.
- CryptoHashUtil.createHashWithKey() replaced custom HMAC with javax.crypto.Mac (HmacSHA256).
- SecurityManagerProviderFactory methods now throw GeneralSecurityException instead of returning null.
- SecurityManagerProviderFactory trust keystore uses getPath() instead of getName() for consistent file resolution.
- CertificateVerifier verifies self-signed root certificates with their own public key.
- CertificateVerifier exception wrapping now preserves the original cause.
- KeyConverterFactory throws IllegalArgumentException for unsupported key algorithms instead of silent RSA fallback.
- ToolariumTrustManager uses ConcurrentHashMap and volatile fields for thread safety.
- ToolariumTrustManager rejects empty/null certificate chains with CertificateException.
- ToolariumKeyManager logs private key info at DEBUG level instead of INFO.
- Sensitive data (challenge nonces, signatures) no longer logged; only metadata (length/size).
- Javadoc algorithm examples updated from SHA1withRSA to SHA256withRSA/SHA256withECDSA.
- CertificateStore file permissions use POSIX owner-only on Unix, best-effort on Windows.
- DER parser: added recursion depth limits, bounds checks, and max length validation (32 MB).
- DER parser: replaced InputStream.available() with full stream read for indefinite-length encoding.
- DER parser: DERInputBuffer.toByteArray() returns empty array instead of null.
- DER parser: DERInputStream.init() propagates errors instead of swallowing silently.
- Cached SecureRandom and BouncyCastleProvider instances for performance.
- Cached default trust keystore to avoid rebuilding on every call.
- CryptUtil.isStrongEncryptionEnabled() no longer permanently caches transient failures.
- CryptUtil.createSecretKeySpec() zeroes key material after use.
- RSAPrivateKeyPKCS8 uses defensive copying in constructor and getEncoded().
- Resource leaks fixed: try-with-resources in KeyStoreUtil, CertificateStore, SSLUtil.
- HashId.encode() padding loop guards against infinite recursion.
- CertificateFilter null-safe for all filter methods.
- KeyStoreUtil.writePKCS12KeyStore() logs warning instead of silently overwriting corrupted keystores.
- All LOG.debug() calls guarded with LOG.isDebugEnabled() where string concatenation is involved.
- JsonSignatureUtil validation logic fixed (AND to OR) and verify uses quoted key matching.

### Added
- CertificateVerifier: opt-in certificate revocation checking (CRL/OCSP) via setRevocationEnabled().

### Deprecated
- CryptoHashUtil.md5(): MD5 is cryptographically broken, use sha256() or sha512().
- CryptoHashUtil.sha1(): SHA-1 is cryptographically weak, use sha256() or sha512().
- KeyStoreUtil.getTrustAllCertificateManager(): insecure, disables all certificate validation.

## [ 1.1.5 ] - 2025-01-03
### Added
- Added class com.github.toolarium.security.configuration.PKIConfigurationUtil.

### Changed
- Removed FileUtil and use FileUtil from toolarium-common.

## [ 1.1.4 ] - 2025-01-01
### Added
- Added class com.github.toolarium.security.test.JavaSecurityTester.

### Changed
- Updated library dependencies.

## [ 1.1.3 ] - 2024-08-03
### Changed
- Updated javadoc.
- Enhanced interface of ISecuritManagerProvider.

## [ 1.1.2 ] - 2024-06-28
### Changed
- Updated library dependencies.

## [ 1.1.1 ] - 2023-12-27
### Added
- Added CertificateTestUtil.

### Fixed
- KeyStoreUtil adding certificates.

## [ 1.1.0 ] - 2023-12-26
### Changed
- Refactoring APIs.

### Added
- Extended test cases.
- JSON signatire support.
- Added modulo 10 and 11 support.

## [ 1.0.4 ] - 2023-12-22
### Added
- Enhanced EC support.

## [ 1.0.3 ] - 2023-12-11
### Fixed
- Index issue bugfix.

## [ 1.0.2 ] - 2023-12-11
### Added
- Enhanced KeyStoreUtil.

### Fixed
- Stabilized tests.

## [ 1.0.1 ] - 2023-12-10
### Fixed
- Updated Bouncy Castle library.

## [ 1.0.0 ] - 2023-12-10
### Added
- Test several cases.
- Finalised implementation.

## [ 0.2.0 ] - 2023-08-03
### Added
- Added ISecurityManagerProvider, IKeyStoreConfiguration and KeyStoreUtil.
- Additional test cases.

## [ 0.1.0 ] - 2023-07-25
### Added
- Setup initial version.
- PKIUtuil class and tests from jpTools.
- Added RSAPrivateKeyPKCS8 classes and tests from jpTools.
- CertificateStore implemented.
- CertificateChainAnalyzeUtil added.
