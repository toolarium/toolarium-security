[![License](https://img.shields.io/github/license/toolarium/toolarium-security)](https://github.com/toolarium/toolarium-security/blob/master/LICENSE)
[![Maven Central](https://img.shields.io/maven-central/v/com.github.toolarium/toolarium-security/0.2.0)](https://search.maven.org/artifact/com.github.toolarium/toolarium-security/0.2.0/jar)
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
    implementation "com.github.toolarium:toolarium-security:0.2.0"
}
```

### Maven:

```xml
<dependency>
    <groupId>com.github.toolarium</groupId>
    <artifactId>toolarium-security</artifactId>
    <version>0.2.0</version>
</dependency>
```


### Samples:

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
