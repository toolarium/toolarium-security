/*
 * CryptoHashUtilTest.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.hash;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;

import com.github.toolarium.common.util.StringUtil;
import java.io.UnsupportedEncodingException;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.util.Arrays;
import org.junit.jupiter.api.Test;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * Test the {@link CryptoHashUtil}.
 * 
 * @author patrick
 */
public class CryptoHashUtilTest {
    private static final Logger LOG = LoggerFactory.getLogger(CryptoHashUtilTest.class);
    private static final String TEST_MESSAGE = "Test";

    
    /**
     * MD5 Test
     * 
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testMd5() throws GeneralSecurityException {
        final byte[] digest = CryptoHashUtil.getInstance().md5(TEST_MESSAGE.getBytes());

        // check the response
        assertNotNull(digest);
        assertEquals("0C:BC:66:11:F5:54:0B:D0:80:9A:38:8D:C9:5A:61:5B", StringUtil.getInstance().toString(digest));
    }

    
    /**
     * SHA1 Test
     * 
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testSHA1() throws GeneralSecurityException {
        final byte[] digest = CryptoHashUtil.getInstance().sha1(TEST_MESSAGE.getBytes());

        // check the response
        assertNotNull(digest);
        assertEquals("64:0A:B2:BA:E0:7B:ED:C4:C1:63:F6:79:A7:46:F7:AB:7F:B5:D1:FA", StringUtil.getInstance().toString(digest));
    }

    
    /**
     * SHA256 Test
     * 
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testSHA256() throws GeneralSecurityException {
        final byte[] digest = CryptoHashUtil.getInstance().sha256(TEST_MESSAGE.getBytes());

        // check the response
        assertNotNull(digest);
        assertEquals("53:2E:AA:BD:95:74:88:0D:BF:76:B9:B8:CC:00:83:2C:20:A6:EC:11:3D:68:22:99:55:0D:7A:6E:0F:34:5E:25", StringUtil.getInstance().toString(digest));
    }

    
    /**
     * SHA512 Test
     * 
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testSHA512() throws GeneralSecurityException {
        final byte[] digest = CryptoHashUtil.getInstance().sha512(TEST_MESSAGE.getBytes());

        // check the response
        assertNotNull(digest);
        assertEquals("C6:EE:9E:33:CF:5C:67:15:A1:D1:48:FD:73:F7:31:88:84:B4:1A:DC:B9:16:02:1E:2B:C0:E8:00:A5:C5:DD:97:F5:14:21:78:F6:AE:88:C8:FD:D9:8E:1A:FB:0C:E4:C8:D2:C5:4B:5F:37:B3:0B:7D:A1:99:7B:B3:3B:0B:8A:31", 
                     StringUtil.getInstance().toString(digest));
    }

    
    /**
     * SHA Test
     * 
     * @throws GeneralSecurityException in case of error
     */
    @Test
    public void testSHA() throws GeneralSecurityException {
        doMessageDigest(null, "SHA1");
        doMessageDigest(null, "SHA-256");
        doMessageDigest(null, "SHA-384");
        doMessageDigest(null, "SHA-512");
    }

    
    /**
     * Hash test with key
     *
     * @throws GeneralSecurityException in case of error
     * @throws UnsupportedEncodingException in case of error
     */
    @Test
    public void testHashWithKey() throws GeneralSecurityException, UnsupportedEncodingException {
        String key1 = "MyPrivateKey1";
        String key2 = "MyPrivateKey2";
        String key3 = "MyPrivateKey1MyPrivateKey2MyPrivateKey3MyPrivateKey4MyPrivateKey5";
        String message = "My private message to be hashed.";
        byte[] digest1 = CryptoHashUtil.getInstance().createHashWithKey(null, key1.getBytes(StandardCharsets.UTF_8.name()), message.getBytes(StandardCharsets.UTF_8.name()));
        byte[] digest2 = CryptoHashUtil.getInstance().createHashWithKey(null, key1.getBytes(StandardCharsets.UTF_8.name()), message.getBytes(StandardCharsets.UTF_8.name()));
        byte[] digest3 = CryptoHashUtil.getInstance().createHashWithKey(null, key2.getBytes(StandardCharsets.UTF_8.name()), message.getBytes(StandardCharsets.UTF_8.name()));
        byte[] digest4 = CryptoHashUtil.getInstance().createHashWithKey(null, key3.getBytes(StandardCharsets.UTF_8.name()), message.getBytes(StandardCharsets.UTF_8.name()));

        LOG.debug("Hash [" + new String(digest1) + "]");
        LOG.debug("Hash [" + new String(digest2) + "]");
        LOG.debug("Hash [" + new String(digest3) + "]");
        LOG.debug("Hash [" + new String(digest4) + "]");

        assertNotNull(digest1);
        assertNotNull(digest2);
        assertNotNull(digest3);
        assertNotNull(digest4);

        assertEquals(Arrays.toString(digest1), Arrays.toString(digest1));
        assertEquals(Arrays.toString(digest2), Arrays.toString(digest2));
        assertEquals(Arrays.toString(digest3), Arrays.toString(digest3));
        assertEquals(Arrays.toString(digest4), Arrays.toString(digest4));

        assertEquals(Arrays.toString(digest1), Arrays.toString(digest2));
        assertEquals(Arrays.toString(digest2), Arrays.toString(digest1));

        assertNotEquals(Arrays.toString(digest2), Arrays.toString(digest3));
        assertNotEquals(Arrays.toString(digest3), Arrays.toString(digest2));
        assertNotEquals(Arrays.toString(digest1), Arrays.toString(digest3));
        assertNotEquals(Arrays.toString(digest3), Arrays.toString(digest1));
        assertNotEquals(Arrays.toString(digest1), Arrays.toString(digest4));
    }


    /**
     * Test the message digest with different values
     *
     * @param provider the provider
     * @param algorithm the algorithm
     * @throws GeneralSecurityException in case of error
     */
    protected void doMessageDigest(String provider, String algorithm) throws GeneralSecurityException {
        doMessageDigest(provider, algorithm, new byte[] {(byte) 0xA9, (byte) 0x9B, (byte) 0xC8, (byte) 0x32, (byte) 0x56, (byte) 0x34, (byte) 0xE3, (byte) 0x03 });
        doMessageDigest(provider, algorithm, "");
        doMessageDigest(provider, algorithm, "    ");
        doMessageDigest(provider, algorithm, "1");
        doMessageDigest(provider, algorithm, "1sadlösdfjlö2349fklödkdfue8ollcas1riefü¨4'$RGs149urpigöfé54¨'9'W)i0adclxmläw45pü45040ü");
    }

    
    /**
     * Test the message digest with the given value
     *
     * @param provider the provider
     * @param algorithm the algorithm
     * @param data the data
     * @throws GeneralSecurityException in case of error
     */
    protected void doMessageDigest(String provider, String algorithm, String data) throws GeneralSecurityException {
        doMessageDigest(provider, algorithm, data.getBytes());
    }

    
    /**
     * Test the message digest with the given value
     *
     * @param provider the provider
     * @param algorithm the algorithm
     * @param data the data
     * @throws GeneralSecurityException in case of error
     */
    protected void doMessageDigest(String provider, String algorithm, byte[] data) throws GeneralSecurityException {
        byte[] digest1 = CryptoHashUtil.getInstance().createHash(provider, algorithm, data);
        byte[] digest2 = CryptoHashUtil.getInstance().createHash(provider, algorithm, data);

        assertNotNull(digest1);
        assertNotNull(digest2);
        assertEquals(Arrays.toString(digest1), Arrays.toString(digest2));
    }
}
