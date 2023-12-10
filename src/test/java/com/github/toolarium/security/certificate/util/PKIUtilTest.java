/*
 * PKIUtilTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate.util;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.toolarium.common.ByteArray;
import java.io.DataInputStream;
import java.io.FileInputStream;
import java.nio.file.Paths;
import java.security.PrivateKey;
import java.security.cert.X509Certificate;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Test the {@link PKIUtil}.
 * 
 * @author patrick
 */
public class PKIUtilTest {

    /** the certificate test file */
    public static final String TEST_CERTFILE = "testcertificate.crt";
    
    /** the RSA certificate test file */
    public static final String TEST_RSA_KEYFILE = "testprivatekey.pem";

    /** Defines the resource */
    public static final String TEST_RESOURCE_PATH = "src/test/resources";
    
    private static final String TEST_CERT = "MIIDZjCCAs+gAwIBAgIBADANBgkqhkiG9w0BAQQFADBvMQ0wCwYDVQQDEwRUZXN0"
            + "MQswCQYDVQQGEwJDSDEUMBIGA1UECBMLU3dpdHplcmxhbmQxDTALBgNVBAoTBFRl"
            + "c3QxEjAQBgNVBAsTCVRlc3QgdW5pdDEYMBYGCSqGSIb3DQEJARYJdGVzdEB0ZXN0"
            + "MB4XDTAzMDcyMTEyMzA1N1oXDTA0MDcyMDEyMzA1N1owbzENMAsGA1UEAxMEVGVz"
            + "dDELMAkGA1UEBhMCQ0gxFDASBgNVBAgTC1N3aXR6ZXJsYW5kMQ0wCwYDVQQKEwRU"
            + "ZXN0MRIwEAYDVQQLEwlUZXN0IHVuaXQxGDAWBgkqhkiG9w0BCQEWCXRlc3RAdGVz"
            + "dDCBnzANBgkqhkiG9w0BAQEFAAOBjQAwgYkCgYEA8wbYUTo/rKXninHN+kXGoHh7"
            + "d3vwrms7cwPT1CJkOCZMRq5sGNpQLRuLP1R336h2URteLGAYjhRmw41MkPbzH85C"
            + "YD26u4rW6kfCTzFQhuC3dan/qe2kx6PlyTbRUBWnS871608vFisvlol2vcC2ii9x"
            + "5ei9eJmyT+0zmao80A8CAwEAAaOCARAwggEMMA8GA1UdEwEB/wQFMAMBAf8wHQYD"
            + "VR0OBBYEFE1N3v0SYct89ZMd2shkz7S1O7OZMIGZBgNVHSMEgZEwgY6AFE1N3v0S"
            + "Yct89ZMd2shkz7S1O7OZoXOkcTBvMQ0wCwYDVQQDEwRUZXN0MQswCQYDVQQGEwJD"
            + "SDEUMBIGA1UECBMLU3dpdHplcmxhbmQxDTALBgNVBAoTBFRlc3QxEjAQBgNVBAsT"
            + "CVRlc3QgdW5pdDEYMBYGCSqGSIb3DQEJARYJdGVzdEB0ZXN0ggEAMAsGA1UdDwQE"
            + "AwIBBjARBglghkgBhvhCAQEEBAMCAAcwHgYJYIZIAYb4QgENBBEWD3hjYSBjZXJ0"
            + "aWZpY2F0ZTANBgkqhkiG9w0BAQQFAAOBgQDhpcQSeiy0kGLqWPAdeuGzj8z7Tbvt"
            + "Fib1mLjui1yGMkAIER140Q91GDccxKveYjxuaWxx4V9oPbcsrpCPj0CsSpX3MOnF"
            + "/Yp9HD29z7uPSDlsedx/85xWqM2lDN/WZ2I6XHXCAlsIbEDelYuAx6VVKrsAYgn9"
            + "kpXe4QZud3KCBQ==";
    private static final String TEST_RSA_PRIVATE_KEY = "MIICXQIBAAKBgQDLj0AFhZuP5p4k5YZgekZNhhnGTMVB/EBTGOocnEJD/4PfS7hfTOu6OJ9zWy4COvpmb8sBdJnRioF4LIQ+jdifuMt+sXAQ5xI4B/NIVaV8Fx5ZwiJEVpXhL2GCr5LQUbC"
            + "pYG04JSiCHeyr4JdbcY65ulMRMa9pQdqkhzH4pzfn2wIDAQABAoGBALmUK6XdHOmgMmUo681hLF7Y9v6WVu/FbU9U03qp6q/bbvpQKhKYKgBoRtYANn3KDyb8nHMDPoiOYWKSEy6EWwwCIOkUTxLxAnYHe7uVbavrFq0EWmpNqca1aELsqqeRJSj"
            + "in4uqo+mjuYatAgjcxezrB+NcyoSxt+P1XAsMF7whAkEA6vKK3EnAKPbsXr2k77ffvlUuibB8Y4mCD/WxxZ/E/sHVz6r4PLZLzQahfQlcvRgO6RmkX2fMSKFF4VJqKItaDQJBAN3Ms6Slie8VNyeiP/jNDwSs471Fe8Ap0G4KYaVRySKmdVaN2NO"
            + "opLDCNeSfbx9YaQj5DyfhFVq5Lr10vy9lV4cCQQDKTJlAYMhy/Vo9oXGZb2vaSSJPMIWKd2ZkM5wknBNVgLWHoKEqNZVDLohyT1NpBoQgNhIQjCGcEDFJeFssGgEpAkAc+ukiAyshnQEG4bFAHfLvZnOfQFvqAMymBB88DZKdP2indYM2LJvQKKA"
            + "IDjjjvJaEwJ4VVNiIcRfFU2LDm5czAkAM5JOBzd6VnBLjXYnwooCdTXrP4DOnCAry+vUBcsSR/Rj3sGCqF077gIQfibtZIVMbcJ7w9y9/SBddFWh9xtDV";
    private static final Logger LOG = LoggerFactory.getLogger(PKIUtilTest.class);

    
    /**
     * Test
     * 
     * @throws Exception in case of error
     */
    @Test
    public void testFormatCertificate() throws Exception {
        DataInputStream dis = new DataInputStream(new FileInputStream(Paths.get(TEST_RESOURCE_PATH, TEST_CERTFILE).toFile()));
        byte[] bytes = new byte[dis.available()];
        dis.readFully(bytes);
        ByteArray buf2 = PKIUtil.getInstance().formatPKCS7(new ByteArray(bytes));
        ByteArray buf1 = PKIUtil.getInstance().formatPKCS7(new ByteArray(TEST_CERT));

        assertEquals(buf1.toString(), buf2.toString());
        /*
        if (!buf1.equals(buf2)) {
            assertNotNull(buf1);
            assertNotNull(buf2);

            Diff diff = new Diff();
            diff.diff(buf1, buf2);
            // log.debug( "'"+diff.getHexDump( true )+"'" );
            assertFalse(diff.getDifferences().isEmpty());
        } else {
            assertEquals(buf1, buf2);
        }
        */
    }
    
    
    /**
     * Test
     * 
     * @throws Exception in case of error
     */
    @Test
    public void testFormatCertificateChain() throws Exception {
        String cert1 = PKIUtil.getInstance().formatPKCS7(new ByteArray(TEST_CERT)).toString();

        String cert2 = PKIUtil.getInstance().formatPKCS7(new ByteArray(TEST_CERT)).toString();
        ByteArray  result = PKIUtil.getInstance().formatPKCS7(new ByteArray(cert1 + "\n" + cert2));
     
        String cert3 = PKIUtil.PUBLIC_CERTIFICATE_START + "\n" + insertCharacter(TEST_CERT, 64, ' ') + "\n" + PKIUtil.PUBLIC_CERTIFICATE_END;
        ByteArray testCertificateChain = PKIUtil.getInstance().formatPKCS7(new ByteArray(cert3 + "\n" + cert3));

        X509Certificate[] certificates = PKIUtil.getInstance().getX509Certificates(testCertificateChain);
        String certificateChainContent = "";
        for (int i = 0; i < certificates.length; i++) {
            if (i > 0) {
                certificateChainContent += "\n";
            }

            certificateChainContent += PKIUtil.getInstance().formatPKCS7(certificates[i]).toString();
        }
        
        PKIUtil.getInstance().processCertificate(LOG::debug, null, certificates);
        assertEquals(result.toString(), certificateChainContent);
    }
    
    
    /**
     * Test
     * 
     * @throws Exception in case of error
     */
    @Test
    public void testReadFileCertificate() throws Exception {
        X509Certificate[] certs = PKIUtil.getInstance().getX509Certificates(Paths.get(TEST_RESOURCE_PATH, TEST_CERTFILE).toString());
        checkCertificates(certs);
    }

    
    /**
     * Test
     * 
     * @throws Exception in case of error
     */
    @Test
    public void testReadBufferCertificate() throws Exception {
        X509Certificate[] certs = PKIUtil.getInstance().getX509Certificates(new ByteArray(TEST_CERT));
        checkCertificates(certs);
    }

    
    /**
     * Testmethod for parseCertificate(String).
     * 
     * @exception Exception in case of error 
     */
    @Test
    public void testParseCertificate() throws Exception {

        X509Certificate[] certs = PKIUtil.getInstance().getX509Certificates(new ByteArray(TEST_CERT));
        checkCertificates(certs);

        certs = PKIUtil.getInstance().getX509Certificates(PKIUtil.getInstance().formatPKCS7(new ByteArray(TEST_CERT)));
        checkCertificates(certs);
    }

    
    /**
     * Test
     * 
     * @throws Exception in case of error
     */
    @Test
    public void testReadPrivateKeyFromFile() throws Exception {
        PrivateKey key = PKIUtil.getInstance().getRSAPrivateKey(Paths.get(TEST_RESOURCE_PATH, TEST_RSA_KEYFILE).toString());

        assertNotNull(key);
        assertEquals("RSA", key.getAlgorithm());
        assertEquals("PKCS#8", key.getFormat());
        assertNotNull(key.getEncoded());
    }

    
    /**
     * Test
     * 
     * @throws Exception in case of error
     */
    @Test
    public void testReadPrivateKeyFromBuffer() throws Exception {
        PrivateKey key = PKIUtil.getInstance().getRSAPrivateKey(new ByteArray(TEST_RSA_PRIVATE_KEY));
        assertNotNull(key);
    }

    
    /**
     * Test
     * 
     * @throws Exception in case of error
     */
    @Test
    public void testNormalizePrivateKeyFromBuffer() throws Exception {
        ByteArray data = new ByteArray(TEST_RSA_PRIVATE_KEY);
        ByteArray wellFormed = PKIUtil.getInstance().formatRSAPKCS8(data);
        ByteArray normalizedForm = PKIUtil.getInstance().normalizeRSAPKCS8(wellFormed);
        assertEquals(data, normalizedForm);
        PrivateKey key = PKIUtil.getInstance().getRSAPrivateKey(normalizedForm);
        assertNotNull(key);
    }
    
    
    /**
     * Check the given certificate chain
     * @param certs the certificates to test
     */
    private void checkCertificates(X509Certificate[] certs) {
        assertNotNull(certs);
        assertTrue(certs.length > 0);

        for (int i = 0; i < certs.length; i++) {
            assertNotNull(certs[i]);
        }

        PKIUtil.getInstance().processCertificate(LOG::debug, null, certs[0]);
    }


    /**
     * Inserts the given char in the given string. Each length of the given
     * value groupLen will the given char inserted.
     * 
     * @param source The field to fill with leading zeros
     * @param groupLen the len of each space group
     * @param data the character to insert
     * @return the modified string
     */
    private String insertCharacter(String source, int groupLen, char data) {
        if (source == null) {
            return null;
        }

        if (groupLen <= 0) {
            return source;
        }

        StringBuilder ref = new StringBuilder();
        for (int i = 0; i < source.length(); i++) {
            ref.append(source.charAt(i));

            if ((((i + 1) % groupLen) == 0) && (i + 1 < source.length())) {
                ref.append(data);
            }
        }

        return ref.toString();
    }
}
