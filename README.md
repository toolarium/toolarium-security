[![License](https://img.shields.io/github/license/toolarium/toolarium-security)](https://github.com/toolarium/toolarium-security/blob/master/LICENSE)
[![Maven Central](https://img.shields.io/maven-central/v/com.github.toolarium/toolarium-security/1.2.0)](https://search.maven.org/artifact/com.github.toolarium/toolarium-security/1.2.0/jar)
[![javadoc](https://javadoc.io/badge2/com.github.toolarium/toolarium-security/javadoc.svg)](https://javadoc.io/doc/com.github.toolarium/toolarium-security)

# toolarium-security

Java security utility library covering certificates, keystores, signing, hashing, SSL/TLS, and more.
Some classes originate from [jpTools](https://jptools.sourceforge.net/) and have been adopted with the permission of the project.


## Built With

* [cb](https://github.com/toolarium/common-build): The toolarium common build


## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/toolarium/toolarium-security/tags).


## Dependency

### Gradle:

```groovy
dependencies {
    implementation "com.github.toolarium:toolarium-security:1.2.0"
}
```

### Maven:

```xml
<dependency>
    <groupId>com.github.toolarium</groupId>
    <artifactId>toolarium-security</artifactId>
    <version>1.2.0</version>
</dependency>
```


## Features

### Hashing

#### Cryptographic hashes (SHA-256, SHA-512, HMAC, …)
```java
byte[] digest = CryptoHashUtil.getInstance().sha256("content".getBytes());
byte[] digest = CryptoHashUtil.getInstance().sha512("content".getBytes());
byte[] digest = CryptoHashUtil.getInstance().createHash(/*provider*/null, "SHA-256", "content".getBytes());
byte[] hmac   = CryptoHashUtil.getInstance().createHashWithKey(/*provider*/null, keyBytes, "content".getBytes());   // HmacSHA256
```

#### URL-safe hash IDs (YouTube-style short IDs from numbers)
```java
HashId hashId = HashId.createHashId("my-salt", /*minLength*/8);
String encoded = hashId.encrypt(1L, 2L, 3L);   // e.g. "aBcDeFgH"
long[] decoded = hashId.decrypt(encoded);      // [1, 2, 3]
```


### Certificates & PKI

#### Generate a self-signed certificate
```java
CertificateStore certificateStore = CertificateUtilFactory.getInstance().getGenerator()
    .createCreateCertificate("MyCertificate");   // RSA-2048, valid 3 years, localhost SAN, end-entity (no CA)

// or with full control
CertificateStore certificateStore = CertificateUtilFactory.getInstance().getGenerator()
    .createCreateCertificate(
        PKIUtil.getInstance().generateKeyPair("RSA", 2048),
        "CN=MyCertificate", "localhost", new Date(), 2 * 365);

// persist: passwords are always char[], zeroed by the library after use.
// Files are created with owner-only permissions on POSIX systems.
char[] password = "changeit".toCharArray();
certificateStore.write("keystore.p12", "myalias", password);
certificateStore.writeCertificate("certificate.crt");
certificateStore.writePublicKey("public.pub");
certificateStore.writePrivateKey("private.pem");
```

#### Create a CA and sign certificates
```java
ICertificateGenerator generator = CertificateUtilFactory.getInstance().getGenerator();

// root CA (new RSA-2048 key pair)
CertificateStore rootCa = generator.createCACertificate("My Root CA", 10 * 365);

// intermediate CA signed by the root CA
CertificateStore intermediateCa = generator.createCACertificate(
    PKIUtil.getInstance().generateKeyPair("RSA", 2048), rootCa, "My Intermediate CA", new Date(), 5 * 365);

// server certificate with its own key pair, signed by the intermediate CA
CertificateStore server = generator.createCreateCertificate(
    PKIUtil.getInstance().generateKeyPair("RSA", 2048), intermediateCa,
    "server.example.com", "server.example.com", new Date(), 365);
```
A CA certificate has no host name and can not be used as server certificate.
The parent of a new certificate must be a CA certificate; `CertificateUtilFactory.getInstance().getGenerator(true)` also accepts a parent which is no CA (behaviour of version 1.1.8 and older).
Without a host name (`alternativeDn` null) the certificate gets the dn and `localhost` as subject alternative names, otherwise only the given host name.

#### Verify a certificate chain
```java
CertificateVerifier verifier = CertificateUtilFactory.getInstance().createVerifier(/*revocationEnabled*/false);

// optional: only accept chains which end in one of these root certificates
verifier.setTrustedCertificates(trustKeyStore);   // or a Collection<X509Certificate>

// optional: enable CRL/OCSP revocation checking (disabled by default)
verifier.setRevocationEnabled(true);
verifier.setRevocationStrict(true);   // reject if the revocation status can not be determined

verifier.verifyCertificateChain(LOG::debug, certificateChain);
```
The issuer name of each certificate must be the subject name of the next certificate in the chain.
By default the chain validation is strict: expired or not yet valid certificates, issuers which are no CA, a violated path length, unknown critical extensions and name constraints are rejected.
Without trusted certificates the root certificate is only verified with its own signature.
`setStrictChainValidation(false)` verifies the signatures only.
`getVerifier()` and `createVerifier(...)` return a new verifier on every call.

#### Convert PEM / DER strings to key and certificate objects
```java
// Parse PEM strings (e.g. from a configuration): the key type is taken from the key itself
PrivateKey privateKey = PKIConfigurationUtil.getInstance().getPrivateKey(privateKeyPem);
PublicKey publicKey = PKIConfigurationUtil.getInstance().getPublicKey(publicKeyPem);
X509Certificate[] certificates = PKIConfigurationUtil.getInstance().getCertificate(certificatePem);
TrustManager[] trustManagers = PKIConfigurationUtil.getInstance().getTrustManagers("myalias", certificatePem);

// Convert individual keys
PrivateKey priv = KeyConverterFactory.getInstance().getConverter("RSA").getPrivateKey(pemString);
PublicKey  pub  = KeyConverterFactory.getInstance().getConverter("RSA").getPublicKey(pemString);
String pemPriv  = KeyConverterFactory.getInstance().getConverter("EC").formatPrivateKey(keyPair.getPrivate());
```
Keys are written with the standard PEM headers `-----BEGIN PRIVATE KEY-----` and `-----BEGIN PUBLIC KEY-----`.
Reading accepts the standard headers, the old type specific headers (e.g. `-----BEGIN RSA PRIVATE KEY-----`) and RSA keys in PKCS#1 format.
Version 1.1.8 and older can only read the old headers; see [System properties](#system-properties).

#### Create a self-signed certificate and use it for a service and client
```java
// 1. Create a self-signed certificate (in-memory) and wrap it in a SecurityManagerProvider.
//    The provider holds both the key store (for the server) and the trust store
//    (with the self-signed cert added so the client can trust it).
ISecurityManagerProvider securityManagerProvider = SecurityManagerProviderFactory.getInstance()
    .getSecurityManagerProvider("myalias", "changeit".toCharArray());

// 2. SSL server: the self-signed certificate is presented to connecting clients
SSLContext serverCtx = SSLContextFactory.getInstance().createSslContext(securityManagerProvider);
SSLServerSocket serverSocket = SSLUtil.getInstance()
    .getSSLServerSocket(serverCtx, port, /*propagateHotName*/false, LOG::debug);

// 3. SSL client: the self-signed certificate is already in the trust store,
//    so the client accepts connections to the same server without a CA
SSLContext clientCtx = SSLContextFactory.getInstance().createSslContext(securityManagerProvider);
```

#### Trust manager with explicitly trusted certificates
```java
ToolariumTrustManager trustManager = new ToolariumTrustManager("server.example.com");
trustManager.addTrustedCertificate(caCertificate);
trustManager.addTrustedCertificate(serverCertificate);

// optional: CRL/OCSP revocation checking (disabled by default)
trustManager.setRevocationEnabled(true);
```
The host name is checked against the subject alternative names first (wildcards like `*.example.com` are supported).
An IP address only matches an IP address subject alternative name.
Without a configured host name the host name of the connection (SSLSocket / SSLEngine) is checked; if it is not known, the host name check is skipped and a warning is logged.
The host name is only checked for server certificates, not for client certificates.
While the verification is switched off (`setVerifyCertificate(false)`) every certificate is accepted, but none is added to the trusted certificates.

#### Analyze a certificate chain
```java
ICertificateChainAnalyzer analyzer = CertificateUtilFactory.getInstance().geChainAnalyzer();

// build the chain of a key from a set of certificates (leaf first)
List<X509Certificate> chain = analyzer.buildChainFor(keyPair.getPublic(), certificates);

// order a chain root first, find the issuer, check self-signed
List<X509Certificate> rootFirst = analyzer.toRootFirst(chain);
X509Certificate issuer = analyzer.getIssuer(chain.get(0), certificates);
boolean selfSigned = analyzer.isSelfSigned(rootFirst.get(0));
```

#### Read, format and filter certificates
```java
// read certificates from a PEM / PKCS#7 file or string
X509Certificate[] certificates = CertificateUtilFactory.getInstance().getConverter().getX509Certificates(new File("certificate.crt"));

// format certificates as PEM
String pem = CertificateUtilFactory.getInstance().getConverter().formatPKCS7(certificates);

// filter by validity
List<X509Certificate> valid = CertificateUtilFactory.getInstance().getFilter().filterValid(Arrays.asList(certificates));
List<X509Certificate> expired = CertificateUtilFactory.getInstance().getFilter().filterExpired(Arrays.asList(certificates));
```


### Keystores

#### Read and write PKCS#12 keystores
```java
// read
ISecuredSecretValue password = SecuredValueFactory.getInstance().createSecret("changeit".toCharArray(), "***");
KeyStore ks = KeyStoreUtil.getInstance().readPKCS12KeyStore("keystore.p12", password);

// write
KeyStoreUtil.getInstance().writePKCS12KeyStore(
    "keystore.p12", /*provider*/null, "myalias", privateKey, certificates, password);

// read a key pair from a PKCS#12 file
CertificateStore certificateStore = KeyStoreUtil.getInstance()
    .readPKCS12KeyPair("keystore.p12", null, "myalias", password);
KeyPair keyPair = certificateStore.getKeyPair();

// the shared default trust keystore (JVM trusted certificates) is read only
KeyStore defaultTrustStore = KeyStoreUtil.getInstance().getDefaultTrustKeyStore();

// a read only view of any loaded keystore: changes throw a KeyStoreException
KeyStore readOnly = new ReadOnlyKeyStore(ks);

// add a certificate to a copy of the default trust keystore (the shared one is not changed)
KeyStore trustStore = KeyStoreUtil.getInstance().addCertificateToTrustKeystore("myalias", certificate);
```
An existing keystore which can not be read (e.g. wrong password) is not overwritten.
Keystores are written atomically and are only readable by the owner on POSIX systems.


### SSL/TLS

#### Create a self-signed SSL context (development / testing)
```java
// Uses SecurityManagerProviderFactory.DEFAULT_ALIAS ("toolarium")
// and SecurityManagerProviderFactory.DEFAULT_PASSWORD ("changit"), for dev/test only.
// Each call creates a new key pair and certificate: create the provider once and reuse it.
ISecurityManagerProvider provider = SecurityManagerProviderFactory.getInstance()
    .getSecurityManagerProvider();
```

#### Create an SSL context with explicit credentials
```java
ISecurityManagerProvider provider = SecurityManagerProviderFactory.getInstance()
    .getSecurityManagerProvider("myalias", "changeit".toCharArray());

// server
SSLContext sslContext = SSLContextFactory.getInstance().createSslContext(provider);
SSLServerSocket serverSocket = SSLUtil.getInstance()
    .getSSLServerSocket(sslContext, port, /*needClientAuth*/true, LOG::debug);

// client
SSLContext sslContext = SSLContextFactory.getInstance().createSslContext(provider);
```

#### Restrict cipher suites
```java
// Specify an explicit allow-list; unsupported suites are logged and skipped.
// Every engine and socket created from the context only enables these suites and the protocols TLSv1.2 / TLSv1.3.
// Without cipher suites the JVM default cipher suites and protocols are used.
SSLContext ctx = SSLContextFactory.getInstance().createSslContext(provider,
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");

// Or use the built-in recommended allowlist (TLS 1.3 + TLS 1.2, forward secrecy, AES-GCM/ChaCha20)
SSLContext ctx = SSLContextFactory.getInstance().createSslContext(provider,
    SSLContextFactory.getInstance().getRecommendedCipherSuites());

// Restrict an engine created elsewhere
SSLContextFactory.getInstance().applyCipherSuites(engine,
    SSLContextFactory.getInstance().getRecommendedCipherSuites());
```

#### Load an SSL context from existing keystore files
```java
ISecuredSecretValue password = SecuredValueFactory.getInstance()
    .createSecret("changeit".toCharArray(), "***");

ISecurityManagerProvider provider = SecurityManagerProviderFactory.getInstance()
    .getSecurityManagerProvider(trustKeyStoreFile, keyStoreFile, password);
```


### Signing

#### Sign and verify data
```java
KeyPair keyPair = PKIUtil.getInstance().generateKeyPair("RSA", 2048);

byte[] signature = SignatureUtil.getInstance()
    .sign(/*provider*/null, "SHA256withRSA", keyPair.getPrivate(), data);

boolean ok = SignatureUtil.getInstance()
    .verify(null, "SHA256withRSA", keyPair.getPublic(), data, signature);
```

#### Sign JSON requests (Alipay-style, see https://global.alipay.com/docs/ac/gr/signature)
```java
Security.addProvider(new BouncyCastleProvider());

KeyPair keyPair = PKIUtil.getInstance().generateKeyPair("BC", "EC", 256);

// serialise keys to PEM for storage / transport
String privatePem = KeyConverterFactory.getInstance().getConverter("EC")
    .formatPrivateKey(keyPair.getPrivate());
String publicPem  = KeyConverterFactory.getInstance().getConverter("EC")
    .formatPublicKey(keyPair.getPublic());

// later: restore keys from PEM
PrivateKey privateKey = KeyConverterFactory.getInstance().getConverter("EC").getPrivateKey(privatePem);
PublicKey  publicKey  = KeyConverterFactory.getInstance().getConverter("EC").getPublicKey(publicPem);

// sign
String signedJson = JsonSignatureUtil.getInstance()
    .sign("BC", "SHA256withECDSA", privateKey, requestJson);

// verify
boolean valid = JsonSignatureUtil.getInstance()
    .verify("BC", "SHA256withECDSA", publicKey, signedJson);
```

#### Challenge / response
```java
KeyPair keyPair = PKIUtil.getInstance().generateKeyPair(null, "RSA", 2048);

byte[] challenge = ChallengeResponseUtil.getInstance().getChallenge(128);
byte[] response  = ChallengeResponseUtil.getInstance()
    .generateResponse(null, "RSA", keyPair.getPrivate(), challenge);

boolean ok = ChallengeResponseUtil.getInstance()
    .checkResponse(null, "RSA", keyPair.getPublic(), challenge, response);
```


### Encryption

#### Encrypt with RSA keys (hybrid encryption)
```java
// defaults: AES with 256 bit key, RSA-OAEP with SHA-256, chunks of 64 KB
byte[] encrypted = CryptionAsymmetric.getInstance().encrypt(keyPair.getPublic(), data);
byte[] decrypted = CryptionAsymmetric.getInstance().decrypt(keyPair.getPrivate(), encrypted);

// text in, Base64 out
String encryptedText = CryptionAsymmetric.getInstance().encrypt(keyPair.getPublic(), "my secret");

// other settings
CryptionAsymmetric cryption = CryptionAsymmetric.builder()
    .provider("BC")
    .aesKeySize(CryptionAsymmetric.AesKeySize.AES_128)
    .oaepHash(CryptionAsymmetric.OaepHash.SHA_512)
    .build();
```

#### Encrypt with an AES key or a passphrase
```java
SecretKey key = CryptionSymmetric.getInstance().generateKey();
byte[] encrypted = CryptionSymmetric.getInstance().encrypt(key, data);
byte[] decrypted = CryptionSymmetric.getInstance().decrypt(key, encrypted);

// passphrase: the key is derived with PBKDF2 and a new salt for every encryption
byte[] encryptedWithPassphrase = CryptionSymmetric.getInstance().encrypt("my-passphrase".toCharArray(), data);

// other settings; data with more PBKDF2 iterations than maxIterations (default 200 000) is rejected when decrypting
CryptionSymmetric cryption = CryptionSymmetric.builder()
    .iterations(300_000)
    .maxIterations(300_000)
    .chunkSize(1024 * 1024)
    .build();
```

#### Encrypt large content as a stream
```java
try (CryptionOutputStream out = new CryptionOutputStream(fileOutputStream, CryptionAsymmetric.getInstance(), keyPair.getPublic())) {
    out.write(data);   // write the content in any number of calls
}

try (CryptionInputStream in = CryptionAsymmetric.getInstance().createInputStream(fileInputStream, keyPair.getPrivate())) {
    int count = in.read(buffer);   // read the content in any number of calls
}

// the same with an AES key or a passphrase
try (CryptionOutputStream out = CryptionSymmetric.getInstance().createOutputStream(fileOutputStream, "my-passphrase".toCharArray())) {
    out.write(data);
}
```
The stream must be closed: the last part of the content is written on `close()`.
The streams and the `encrypt` / `decrypt` methods use the same format: data encrypted with one can be decrypted with the other.
The settings are stored in the encrypted data, every instance can decrypt it.
Modified data is detected and rejected.


### Cipher utilities

#### Check strong encryption / create AES keys
```java
boolean strongEncryption = CryptionUtil.getInstance().isStrongEncryptionEnabled();

// derive an AES key with an own random salt (at least 16 bytes); store the salt with the encrypted data
byte[] salt       = CryptionUtil.getInstance().generateSalt();
SecretKeySpec key = CryptionUtil.getInstance().createSecretKeySpec("my-secret-passphrase".toCharArray(), salt, 100_000);
Cipher cipher     = CryptionUtil.getInstance().getCipher("AES/GCM/NoPadding");
```


### Check digits

#### Modulo 10 / 11
```java
Long   check10 = Modulo10.getInstance().createCheckDigit("12345678");
String check11 = Modulo11.getInstance().createCheckDigit("12345678");

boolean valid10 = Modulo10.getInstance().validate("123456784");
boolean valid11 = Modulo11.getInstance().validate("123456782");
```


## System properties

| Property | Default | Description |
|----------|---------|-------------|
| `toolarium.security.legacyPemHeaders` | `false` | `true` writes the PEM headers of version 1.1.8 and older (e.g. `-----BEGIN RSA PRIVATE KEY-----`) instead of the standard headers. |
| `toolarium.security.trustManagerAlgorithm` | JVM default (`PKIX`) | Algorithm of the trust managers, e.g. `SunX509` for the behaviour of version 1.1.8 and older. |


## Test the security environment

Verify that strong encryption is enabled and `SecureRandom` is working correctly:

```
java -cp build/libs/toolarium-security-1.2.0.jar com.github.toolarium.security.test.JavaSecurityTester
```

#### Output on Windows
```
Java Security Tester: 2025-01-01T16:18:00.444187700Z
> Strong encryption is enabled.
> Secure random, java.security.egd = null took 0.0169983 seconds and used the Windows-PRNG algorithm.
```

#### Output on Linux
```
Java Security Tester: 2025-01-01T16:21:26.753315246Z
> Strong encryption is enabled.
> Secure random, java.security.egd = null took 0.003593073 seconds and used the NativePRNGBlocking algorithm.
```
