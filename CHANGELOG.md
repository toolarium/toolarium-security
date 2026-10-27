# toolarium-security

All notable changes to this project will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.0.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [ 1.2.0 ] - 2026-10-27
### Added
- `ICertificateGenerator.createCACertificate` to create root and intermediate CA certificates. Custom implementations of `ICertificateGenerator` must add these methods.
- `CertificateVerifier`: optional trusted root certificates (`setTrustedCertificates`), switchable strict chain validation (`setStrictChainValidation`) and strict revocation checking (`setRevocationStrict`).
- `CertificateUtilFactory.createVerifier(boolean revocationEnabled)`.
- `ToolariumTrustManager`: host name (`ToolariumTrustManager(String)`, `setHostname`) and revocation checking (`setRevocationEnabled`, `setRevocationStrict`).
- `KeyStoreUtil.addCertificateToTrustKeystore(alias, certificateChain, global)` to change the shared default trust keystore on purpose.
- `SSLContextFactory.getRecommendedCipherSuites()`.
- `CryptUtil.generateSalt()`.
- `RSAPrivateKeyPKCS8.destroy()` to clear the key material.
- System property `toolarium.security.legacyPemHeaders=true` to write the PEM headers of version 1.1.8 and older.
- System property `toolarium.security.trustManagerAlgorithm` to choose the trust manager algorithm (`SunX509` for the old behaviour).

### Changed
- Keys are written with the standard PEM headers, so other tools like OpenSSL can read them. The old headers are still read. Version 1.1.8 and older can not read the new files (see `toolarium.security.legacyPemHeaders`).
- RSA private keys in the traditional OpenSSL format can be loaded; invalid keys are rejected when loaded.
- Certificate chain validation is strict by default: expired certificates and issuers which are no CA are rejected (old behaviour: `setStrictChainValidation(false)`).
- `createCreateCertificate` creates end-entity certificates; a self-signed certificate is no CA anymore. Use `createCACertificate` for a CA.
- `CertificateUtilFactory.getVerifier()` returns a new verifier on every call.
- `ToolariumTrustManager` keeps every trusted certificate, supports wildcard host names and does not remember certificates while the verification is off.
- Revocation checking (off by default) works when it is enabled.
- `SSLContextFactory.createSslContext(provider, allowedCipherSuites...)` enforces the given cipher suites.
- The trust managers use the JVM default algorithm (old behaviour: `-Dtoolarium.security.trustManagerAlgorithm=SunX509`).
- `KeyStoreUtil.writePKCS12KeyStore` does not overwrite an existing keystore which can not be read (e.g. wrong password).
- `KeyStoreUtil.addCertificateToTrustKeystore(alias, ...)` no longer changes the shared default trust keystore.
- Keystore and key files are only readable by the owner on POSIX systems.
- `CryptUtil.createSecretKeySpec(passphrase, salt, iterations)` requires a salt of at least 16 bytes.
- `HashId.encrypt` throws `IllegalArgumentException` for invalid input.
- Logs of routine operations are DEBUG instead of INFO.

### Deprecated
- `SSLContextFactory.RECOMMENDED_CIPHER_SUITES`: use `getRecommendedCipherSuites()`.

### Fixed
- The deprecated `PKIUtil.PUBLIC_*_KEY_START/END` constants contained the private key headers.
- `HashId` handles very large numbers and malformed input.
- `PKIConfigurationUtil` loads generic PEM keys.
- The DER parser rejects malformed input with a clear exception.
- `CryptoHashUtil` accepts a provider name with surrounding spaces.
- Complete Javadoc.

## [ 1.1.8 ] - 2026-10-20
### Changed
- Updated dependencies: toolarium-common 1.2.0.

## [ 1.1.7 ] - 2026-09-20
### Changed
- Updated dependencies: toolarium-common 1.1.0, BouncyCastle 1.86.
- Migrated all password handling from `ISecuredValue<String>` / `String` to `ISecuredSecretValue` / `char[]` across KeyStoreUtil, SecurityManagerProviderFactory, SecurityManagerProviderImpl, CertificateStore, and CertificateGenerator to avoid plaintext password exposure in heap memory.
- Replaced deprecated `SecureSecret.toCharArray()` calls with `useChars(Function)` pattern via a private `withSecret()` helper to ensure temporary char arrays are zeroed automatically.
- CertificateGenerator main method reads keystore password into `char[]` and zeroes it after use.
- JsonSignatureUtil.verify() rewrote signature extraction to use exact structural matching against constants derived from sign() format, plus base64 validation, preventing JSON signature bypass via key-name injection.
- SecurityManagerProviderFactory: added `DEFAULT_ALIAS` and `DEFAULT_PASSWORD` constants for the no-arg convenience method defaults; added `WARNING: FOR DEVELOPMENT/TESTING ONLY` Javadoc on the zero-arg overload.
- CertificateVerifier: revocation check disabled by default — added prominent class-level and constructor-level WARNING Javadoc; `System.setProperty("com.sun.security.enableCRLDP", "true")` is now set lazily inside `verifyRevocation()` only when actually needed (guarded to avoid redundant sets); self-signed root verification site documented that it does not validate against a trust anchor.
- ToolariumTrustManager: documented that `getHostname()` returns null and hostname verification is skipped by default.
- SignatureUtil.sign(): added best-effort `PrivateKey.destroy()` call after signing to zero key material; DEBUG log site annotated with warning about key metadata exposure.
- SSLContextFactory: replaced class-level WARNING comment with usage documentation; added `createSslContext(ISecurityManagerProvider, String...)` overload to allow an explicit cipher suite allow-list, and `applyCipherSuites(SSLEngine, String...)` helper that validates suites against JVM-supported ones.
- CryptUtil: restored `ALGORITHM_AES` constant (was accidentally commented out).
- `volatile` added to `CertificateVerifier.revocationEnabled` for correct multi-threaded visibility.
- CertificateVerifier: replaced `System.setProperty("com.sun.security.enableCRLDP")` with scoped `PKIXRevocationChecker` (PREFER_CRLS + NO_FALLBACK + SOFT_FAIL) to avoid global JVM state and gracefully handle certs without CRL/OCSP endpoints.
- CertificateGenerator: fixed issuer DN to preserve exact DER bytes from parent cert; fixed AuthorityKeyIdentifier on leaf certs to reference the issuer's public key; use JDK-native X509Certificate for PKIX path validator compatibility.
- DERInputStream: added bounds check before `data[offset+1]` access to prevent ArrayIndexOutOfBoundsException on malformed DER input.
- SSLContextFactory: upgraded from `TLSv1.2` to `TLS` context so TLS 1.3 is negotiated when both peers support it; added `RECOMMENDED_CIPHER_SUITES` constant covering TLS 1.3 (AES-GCM, ChaCha20) and TLS 1.2 (ECDHE/DHE + AES-GCM) suites.

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
