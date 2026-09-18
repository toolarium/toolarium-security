[![License](https://img.shields.io/github/license/toolarium/toolarium-security)](https://github.com/toolarium/toolarium-security/blob/master/LICENSE)
[![Maven Central](https://img.shields.io/maven-central/v/com.github.toolarium/toolarium-security/1.1.7)](https://search.maven.org/artifact/com.github.toolarium/toolarium-security/1.1.7/jar)
[![javadoc](https://javadoc.io/badge2/com.github.toolarium/toolarium-security/javadoc.svg)](https://javadoc.io/doc/com.github.toolarium/toolarium-security)

# toolarium-security

Java security utility library covering certificates, keystores, signing, hashing, SSL/TLS, and more.
Some classes originate from [jpTools](https://jptools.sourceforge.net/) and have been adopted with the permission of the project.


## Built With

* [cb](https://github.com/toolarium/common-build) - The toolarium common build


## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/toolarium/toolarium-security/tags).


## Dependency

### Gradle:

```groovy
dependencies {
    implementation "com.github.toolarium:toolarium-security:1.1.7"
}
```

### Maven:

```xml
<dependency>
    <groupId>com.github.toolarium</groupId>
    <artifactId>toolarium-security</artifactId>
    <version>1.1.7</version>
</dependency>
```


## Features

### Hashing

#### Cryptographic hashes (SHA-256, SHA-512, HMAC, …)
```java
byte[] digest = CryptoHashUtil.getInstance().sha256("content".getBytes());
byte[] digest = CryptoHashUtil.getInstance().sha512("content".getBytes());
byte[] digest = CryptoHashUtil.getInstance().createHash(/*provider*/null, "SHA-256", "content");
byte[] hmac   = CryptoHashUtil.getInstance().createHashWithKey(null, "HmacSHA256", keyBytes, "content");
```

#### URL-safe hash IDs (YouTube-style short IDs from numbers)
```java
HashId hashId = new HashId("my-salt", /*minLength*/8);
String encoded = hashId.encode(1L, 2L, 3L);   // e.g. "aBcDeFgH"
long[] decoded = hashId.decode(encoded);       // [1, 2, 3]
```


### Certificates & PKI

#### Generate a self-signed certificate
```java
CertificateStore certificateStore = CertificateUtilFactory.getInstance().getGenerator()
    .createCreateCertificate("MyCertificate");   // RSA-2048, valid 3 years, localhost SAN

// or with full control
CertificateStore certificateStore = CertificateUtilFactory.getInstance().getGenerator()
    .createCreateCertificate(
        PKIUtil.getInstance().generateKeyPair("RSA", 2048),
        "CN=MyCertificate", "localhost", new Date(), 2 * 365);

// persist — passwords are always char[], zeroed by the library after use
char[] password = "changeit".toCharArray();
certificateStore.write("keystore.p12", "myalias", password);
certificateStore.writeCertificate("certificate.crt");
certificateStore.writePublicKey("public.pub");
certificateStore.writePrivateKey("private.pem");
```

#### Verify a certificate chain
```java
CertificateVerifier verifier = (CertificateVerifier) CertificateUtilFactory.getInstance().getVerifier();

// opt-in: enable CRL/OCSP revocation checking (disabled by default)
verifier.setRevocationEnabled(true);
verifier.verifyCertificateChain(LOG::debug, certificateChain);
```

#### Convert PEM / DER strings to key and certificate objects
```java
// Parse a PEM bundle that may contain certificates, private key, and public key
PKIConfigurationUtil.getInstance().convert(pemBundle, keyAlgorithm, trustManagers, keyStore);

// Convert individual keys
PrivateKey priv = KeyConverterFactory.getInstance().getConverter("RSA").getPrivateKey(pemString);
PublicKey  pub  = KeyConverterFactory.getInstance().getConverter("RSA").getPublicKey(pemString);
String pemPriv  = KeyConverterFactory.getInstance().getConverter("EC").formatPrivateKey(keyPair.getPrivate());
```

#### Create a self-signed certificate and use it for a service and client
```java
// 1. Create a self-signed certificate (in-memory) and wrap it in a SecurityManagerProvider.
//    The provider holds both the key store (for the server) and the trust store
//    (with the self-signed cert added so the client can trust it).
ISecurityManagerProvider securityManagerProvider = SecurityManagerProviderFactory.getInstance()
    .getSecurityManagerProvider("myalias", "changeit".toCharArray());

// 2. SSL server — the self-signed certificate is presented to connecting clients
SSLContext serverCtx = SSLContextFactory.getInstance().createSslContext(securityManagerProvider);
SSLServerSocket serverSocket = SSLUtil.getInstance()
    .getSSLServerSocket(serverCtx, port, /*needClientAuth*/false, LOG::debug);

// 3. SSL client — the self-signed certificate is already in the trust store,
//    so the client accepts connections to the same server without a CA
SSLContext clientCtx = SSLContextFactory.getInstance().createSslContext(securityManagerProvider);
```

#### Analyze a certificate chain
```java
CertificateUtilFactory.getInstance().getChainAnalyzer()
    .analyzeCertificateChain(LOG::debug, certificateChain);
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
```


### SSL/TLS

#### Create a self-signed SSL context (development / testing)
```java
// Uses SecurityManagerProviderFactory.DEFAULT_ALIAS ("toolarium")
// and SecurityManagerProviderFactory.DEFAULT_PASSWORD ("changit") — for dev/test only
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
// Specify an explicit allow-list; unsupported suites are logged and skipped
SSLContext ctx = SSLContextFactory.getInstance().createSslContext(provider,
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384",
    "TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384");

// Apply the same restriction to every engine / socket created from the context
SSLEngine engine = ctx.createSSLEngine(host, port);
SSLContextFactory.getInstance().applyCipherSuites(engine,
    "TLS_AES_128_GCM_SHA256",
    "TLS_AES_256_GCM_SHA384");
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

#### Sign JSON requests (Alipay-style — https://global.alipay.com/docs/ac/gr/signature)
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


### Cipher utilities

#### Check strong encryption / create AES keys
```java
boolean strongEncryption = CryptUtil.getInstance().isStrongEncryptionEnabled();

SecretKeySpec key = CryptUtil.getInstance().createSecretKeySpec("my-secret-passphrase");
Cipher cipher     = CryptUtil.getInstance().getCipher("AES/GCM/NoPadding");
```


### Check digits

#### Modulo 10 / 11
```java
char check10 = Modulo10.getInstance().getCheckDigit("12345678");
char check11 = Modulo11.getInstance().getCheckDigit("12345678");

boolean valid10 = Modulo10.getInstance().validate("123456784");
boolean valid11 = Modulo11.getInstance().validate("123456782");
```


## Test the security environment

Verify that strong encryption is enabled and `SecureRandom` is working correctly:

```
java -cp build/libs/toolarium-security-1.1.7.jar com.github.toolarium.security.test.JavaSecurityTester
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
