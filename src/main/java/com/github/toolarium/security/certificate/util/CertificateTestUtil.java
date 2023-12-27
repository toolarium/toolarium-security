/*
 * CertificateTestUtil.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate.util;

import com.github.toolarium.security.certificate.CertificateUtilFactory;
import com.github.toolarium.security.certificate.dto.CertificateStore;
import com.github.toolarium.security.pki.util.PKIUtil;
import java.security.GeneralSecurityException;
import java.security.KeyPair;
import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.Calendar;
import java.util.List;
import java.util.stream.Collectors;


/**
 * Certificate test util.
 *  
 * @author patrick
 */
public final class CertificateTestUtil {

    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     */
    private static class HOLDER {
        static final CertificateTestUtil INSTANCE = new CertificateTestUtil();
    }

    
    /**
     * Constructor
     */
    private CertificateTestUtil() {
        // NOP
    }

    
    /**
     * Get the instance
     *
     * @return the instance
     */
    public static CertificateTestUtil getInstance() {
        return HOLDER.INSTANCE;
    }

    
    /**
     * Create self signed certificate list:
     * 
     * <pre> 
     *               NOW
     *     -10  -5    0    5    10
     *      .    .    .    .    .
     *   A  [....]
     *   B    [......] 
     *   C  [..........]
     *   D       [.........]
     *   E           [.........]
     *   F                      [.........]
     *   G                 [.........]
     * </pre>
     * @return the certificates
     * @throws GeneralSecurityException In case of a security exception
     */
    public List<X509Certificate> createSelfSignedCertificates() throws GeneralSecurityException {
        // create Key pair
        return createSelfSignedCertificates(PKIUtil.getInstance().generateKeyPair("RSA", 2048));
    }

    
    /**
     * Create self signed certificate list:
     * 
     * <pre> 
     *               NOW
     *     -10  -5    0    5    10
     *      .    .    .    .    .
     *   A  [....]
     *   B    [......] 
     *   C  [..........]
     *   D       [.........]
     *   E           [.........]
     *   F                      [.........]
     *   G                 [.........]
     * </pre>
     * @param keyPair the key pair
     * @return the certificates
     * @throws GeneralSecurityException In case of a security exception
     */
    public List<X509Certificate> createSelfSignedCertificates(KeyPair keyPair) throws GeneralSecurityException {

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
        list.add(createCertificate(keyPair, "A", Calendar.getInstance().get(Calendar.DAY_OF_YEAR) - 10, 5));
        list.add(createCertificate(keyPair, "B", Calendar.getInstance().get(Calendar.DAY_OF_YEAR) - 8, 7));
        list.add(createCertificate(keyPair, "C", Calendar.getInstance().get(Calendar.DAY_OF_YEAR) - 10, 12));
        list.add(createCertificate(keyPair, "D", Calendar.getInstance().get(Calendar.DAY_OF_YEAR) - 5, 10));
        list.add(createCertificate(keyPair, "E", Calendar.getInstance().get(Calendar.DAY_OF_YEAR) - 1, 10));
        list.add(createCertificate(keyPair, "F", Calendar.getInstance().get(Calendar.DAY_OF_YEAR) + 10, 10));
        list.add(createCertificate(keyPair, "G", Calendar.getInstance().get(Calendar.DAY_OF_YEAR) + 5, 10));
        return list;
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
    public X509Certificate createCertificate(KeyPair keyPair, String dn, int dayOfYear, int days) throws GeneralSecurityException {
        Calendar calendar = Calendar.getInstance();
        calendar.set(Calendar.DAY_OF_YEAR, dayOfYear);
        CertificateStore certificateStore = CertificateUtilFactory.getInstance().getGenerator().createCreateCertificate(keyPair, dn, null, calendar.getTime(), days);
        return certificateStore.getCertificates()[0];
    }

    
    /**
     * Convert certificate list to a string expression with DN
     *
     * @param list the list
     * @return the string
     */
    public String toDNList(List<X509Certificate> list) {
        return list
                .stream()
                .map(c -> c.getSubjectX500Principal().getName())
                .collect(Collectors.toList()).toString().replaceAll("CN=", "");

    }
}
