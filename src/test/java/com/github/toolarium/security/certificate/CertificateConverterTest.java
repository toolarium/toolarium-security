/*
 * CertificateConverterTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import com.github.toolarium.security.certificate.dto.CertificateStore;
import com.github.toolarium.security.certificate.impl.CertificateConverter;
import com.github.toolarium.security.certificate.util.PKIUtilTest;
import com.github.toolarium.security.pki.util.PKIUtil;
import com.github.toolarium.security.util.FileUtil;
import java.nio.file.Paths;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.Collections;
import java.util.List;
import java.util.stream.Collectors;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * 
 * @author patrick
 */
public class CertificateConverterTest {
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
    private static final Logger LOG = LoggerFactory.getLogger(PKIUtilTest.class);

    
    /**
     * Test
     * 
     * @throws Exception in case of error
     */
    @Test
    public void testFormatCertificate() throws Exception {
        String content = FileUtil.getInstance().readFileContent(Paths.get(TEST_RESOURCE_PATH, TEST_CERTFILE));
        String buf2 = CertificateUtilFactory.getInstance().getConverter().formatPKCS7(content);
        String buf1 = CertificateUtilFactory.getInstance().getConverter().formatPKCS7(TEST_CERT);

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
        String cert1 = CertificateUtilFactory.getInstance().getConverter().formatPKCS7(TEST_CERT);
        String cert2 = CertificateUtilFactory.getInstance().getConverter().formatPKCS7(TEST_CERT);
        String result = CertificateUtilFactory.getInstance().getConverter().formatPKCS7(cert1 + "\n" + cert2);
        String cert3 = CertificateConverter.PUBLIC_CERTIFICATE_START + "\n" + insertCharacter(TEST_CERT, 64, ' ') + "\n" + CertificateConverter.PUBLIC_CERTIFICATE_END;
        String testCertificateChain = CertificateUtilFactory.getInstance().getConverter().formatPKCS7(cert3 + "\n" + cert3);

        X509Certificate[] certificates = CertificateUtilFactory.getInstance().getConverter().getX509Certificates(testCertificateChain);
        String certificateChainContent = "";
        for (int i = 0; i < certificates.length; i++) {
            if (i > 0) {
                certificateChainContent += "\n";
            }

            certificateChainContent += CertificateUtilFactory.getInstance().getConverter().formatPKCS7(certificates[i]).toString();
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
        X509Certificate[] certs = CertificateUtilFactory.getInstance().getConverter().getX509Certificates(Paths.get(TEST_RESOURCE_PATH, TEST_CERTFILE).toFile());
        checkCertificates(certs);
    }

    
    /**
     * Test
     * 
     * @throws Exception in case of error
     */
    @Test
    public void testReadBufferCertificate() throws Exception {
        X509Certificate[] certs = CertificateUtilFactory.getInstance().getConverter().getX509Certificates(TEST_CERT);
        checkCertificates(certs);
    }

    
    /**
     * Testmethod for parseCertificate(String).
     * 
     * @exception Exception in case of error 
     */
    @Test
    public void testParseCertificate() throws Exception {

        X509Certificate[] certs = CertificateUtilFactory.getInstance().getConverter().getX509Certificates(TEST_CERT);
        checkCertificates(certs);

        certs = CertificateUtilFactory.getInstance().getConverter().getX509Certificates(CertificateUtilFactory.getInstance().getConverter().formatPKCS7(TEST_CERT));
        checkCertificates(certs);
    }

    
    /**
     * Filter certificates
     *
     * @throws GeneralSecurityException In case of a security excpetion
     */
    @Test
    public void testFiltervalidCertificate() throws GeneralSecurityException {
        KeyPair keyPair = PKIUtil.getInstance().generateKeyPair(null, "RSA", 2048);
        
        Calendar calendar = Calendar.getInstance();
        int dayOfYear = calendar.get(Calendar.DAY_OF_YEAR);
        calendar.set(Calendar.DAY_OF_YEAR, dayOfYear);
        calendar.getTime();
        
        /*             <NOW>
              -10  -5    0    5    10
               .    .    .    .    .
            A  [....]
            B    [......] 
            C  [..........]
            D       [.........]
            E           [.........]
            F                      [.........]
            G                 [.........]
         */
        List<X509Certificate> list = new ArrayList<X509Certificate>();
        list.add(getCertificate(keyPair, "A", calendar.get(Calendar.DAY_OF_YEAR) - 10, 5));
        list.add(getCertificate(keyPair, "B", calendar.get(Calendar.DAY_OF_YEAR) - 8, 7));
        list.add(getCertificate(keyPair, "C", calendar.get(Calendar.DAY_OF_YEAR) - 10, 12));
        list.add(getCertificate(keyPair, "D", calendar.get(Calendar.DAY_OF_YEAR) - 5, 10));
        list.add(getCertificate(keyPair, "E", calendar.get(Calendar.DAY_OF_YEAR) - 1, 10));
        list.add(getCertificate(keyPair, "F", calendar.get(Calendar.DAY_OF_YEAR) + 10, 10));
        list.add(getCertificate(keyPair, "G", calendar.get(Calendar.DAY_OF_YEAR) + 5, 10));
        Collections.shuffle(list);
        LOG.debug("==>" + toDNList(list));

        List<X509Certificate> expiredList = CertificateUtilFactory.getInstance().getFilter().filterExpired(list);
        assertEquals("[A, B]", toDNList(expiredList));
        List<X509Certificate> notYetValidList = CertificateUtilFactory.getInstance().getFilter().filterNotYedValid(list);
        assertEquals("[G, F]", toDNList(notYetValidList));
        List<X509Certificate> validList = CertificateUtilFactory.getInstance().getFilter().filterValid(list);
        assertEquals("[C, D, E]", toDNList(validList));
        
    }


    /**
     * Convert certificate list to a string expression with DN
     *
     * @param list the list
     * @return the string
     */
    private String toDNList(List<X509Certificate> list) {
        return list
                .stream()
                .map(c -> c.getSubjectX500Principal().getName())
                .collect(Collectors.toList()).toString().replaceAll("CN=", "");

    }
    
    
    /**
     * Create a certificate
     *
     * @param keyPair the key pair
     * @param dn the dn
     * @param dayOfYear the day of year
     * @param days the validity in days
     * @return the generated certificate
     * @throws GeneralSecurityException In case of a security exception
     */
    private X509Certificate getCertificate(KeyPair keyPair, String dn, int dayOfYear, int days) throws GeneralSecurityException {
        Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.DAY_OF_YEAR, dayOfYear);
        CertificateStore certificateStore = CertificateUtilFactory.getInstance().getGenerator().createCreateCertificate(keyPair, dn, null, calendar.getTime(), days);
        return certificateStore.getCertificates()[0];
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
