[![License](https://img.shields.io/github/license/toolarium/toolarium-security)](https://github.com/toolarium/toolarium-security/blob/master/LICENSE)
[![Maven Central](https://img.shields.io/maven-central/v/com.github.toolarium/toolarium-security/1.0.1)](https://search.maven.org/artifact/com.github.toolarium/toolarium-security/1.0.1/jar)
[![javadoc](https://javadoc.io/badge2/com.github.toolarium/toolarium-security/javadoc.svg)](https://javadoc.io/doc/com.github.toolarium/toolarium-security)

# toolarium-security

Java library with security utilities.
Some of the classes of the [jpTools] (https://jptools.sourceforge.net/) have been adopted with the permission of the project.


## Built With

* [cb](https://github.com/toolarium/common-build) - The toolarium common build

## Versioning

We use [SemVer](http://semver.org/) for versioning. For the versions available, see the [tags on this repository](https://github.com/toolarium/toolarium-security/tags). 


### Gradle:

```groovy
dependencies {
    implementation "com.github.toolarium:toolarium-security:1.0.1"
}
```

### Maven:

```xml
<dependency>
    <groupId>com.github.toolarium</groupId>
    <artifactId>toolarium-security</artifactId>
    <version>1.0.1</version>
</dependency>
```


### Samples:
#### Create hashes, e.g. SHA-256, SHA-512...
```java
byte[] digest1 = CryptoHashUtil.getInstance().sha256("content".getBytes());
byte[] digest2 = CryptoHashUtil.getInstance().createHash(/*provider*/null, "SHA-256", "content")
```

#### Create a self signed certificate:
```java
// create new certificate
CertificateStore certificateStore = 
    X509CertificateGenerator.getInstance().createCreateCertificate(
        PKIUtil.getInstance().generateKeyPair("RSA", 2048), "MyCertificate", "localhost", new Date(), 2 * 365);  // from now until 2 years  

certificateStore.write("mypkc12-cert.p12", "alias", "password");
certificateStore.writeCertificate("mycertificate.crt");
certificateStore.writePublicKey("mypublickey.pub");
certificateStore.writePrivateKey("myprivatekey.pem");
```     

#### Create a self-signed certificate and use it for a service and client
```java
ISecurityManagerProvider securityManagerProvider = SecurityManagerProviderFactory.getInstance().getSecurityManagerProvider("toolarium", "changit");
...
    // create SSL context with self-signed certificate for a SSL server / service
    SSLContext sslContext = SSLContextFactory.getInstance().createSslContext(securityManagerProvider);
    SSLServerSocket s  = SSLUtil.getInstance().getSSLServerSocket(sslContext, port, true, LOG::debug);
...
    // create ssl context with added self-signed certificate in trust store for a SSL client
    SSLContext sslContext = SSLContextFactory.getInstance().createSslContext(securityManagerProvider);
```

#### Use of the challenge / response util
```java
String provider = null;
KeyPair keyPair = PKIUtil.getInstance().generateKeyPair(provider, "RSA", 1024);

// generate challenge
byte[] challenge = ChallengeResponseUtil.getInstance().getChallenge(128);

// generate response of the given challenge
byte[] response = ChallengeResponseUtil.getInstance().generateResponse(provider, "RSA", keyPair.getPrivate(), challenge);

// verify the response and the challenge
assertTrue(ChallengeResponseUtil.getInstance().checkResponse(provider, "RSA", keyPair.getPublic(), challenge, response));
```
