/*
 * RSAPrivateKeyPKCS8.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.pki.impl.rsa;

import com.github.toolarium.security.pki.impl.rsa.der.DERInputStream;
import com.github.toolarium.security.pki.impl.rsa.der.DEROutputStream;
import com.github.toolarium.security.pki.impl.rsa.der.DERValue;
import com.github.toolarium.security.pki.impl.rsa.der.ObjectIdentifier;
import java.io.IOException;
import java.math.BigInteger;
import java.security.GeneralSecurityException;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
import java.util.Arrays;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * This class implements the encoding of a RSA private key
 * 
 * @author patrick
 */
public class RSAPrivateKeyPKCS8 implements RSAPrivateKey {
    private static final long serialVersionUID = 3617009758595528501L;
    private static final Logger LOG = LoggerFactory.getLogger(RSAPrivateKeyPKCS8.class);
    private RSAPrivateCrtKeySpec keyspec;
    private byte[] encoded;
    private volatile boolean destroyed;


    /**
     * Default constructor for RSAPrivateKeyPKCS8
     * 
     * @param encoded the private key as byte array
     */
    public RSAPrivateKeyPKCS8(byte[] encoded) {
        this.encoded = encoded.clone();
        this.keyspec = null;
    }


    /**
     * Copy constructor for RSAPrivateKeyPKCS8
     * 
     * @param keyspec the class
     */
    public RSAPrivateKeyPKCS8(RSAPrivateCrtKeySpec keyspec) {
        this.keyspec = keyspec;
        this.encoded = null;
    }


    /**
     * @see java.security.Key#getAlgorithm()
     */
    @Override
    public String getAlgorithm()  {
        return "RSA";
    }


    /**
     * @see java.security.Key#getFormat()
     */
    @Override
    public String getFormat() {
        return "PKCS#8";
    }


    /**
     * Check the encoding
     * 
     * @throws InvalidKeySpecException in case of error
     */
    public void checkEncoding() throws InvalidKeySpecException {
        checkNotDestroyed();
        byte[] data = getEncoded();

        try {
            DERInputStream dis = new DERInputStream(data);
            DERValue[] derseq = dis.getSequence(3);
            if (derseq == null || derseq.length == 0) {
                throw new InvalidKeySpecException("Empty DER sequence");
            }

            if (!BigInteger.ZERO.equals(derseq[0].getInteger().toBigInteger())) {
                throw new InvalidKeySpecException("Bad DER sequence");
            }
        } catch (IOException e) {
            throw new InvalidKeySpecException(e.getMessage(), e);
        } catch (RuntimeException e) {
            // malformed input must not escape as an unchecked exception
            throw new InvalidKeySpecException("Invalid DER encoding: " + e.getMessage(), e);
        } finally {
            if (data != null) {
                Arrays.fill(data, (byte) 0);
            }
        }

        return;
    }

    
    /**
     * @see java.security.Key#getEncoded()
     */
    @Override
    public synchronized byte[] getEncoded() {
        checkNotDestroyed();
        byte[] result = encoded;
        if (result != null) {
            return result.clone();
        }

        try {
            DERValue[] pkcs8 = new DERValue[3];
            pkcs8[0] = getTwoByteDerValue(new BigInteger("0"));
            pkcs8[1] = init();
            pkcs8[2] = convert(keyspec);

            DEROutputStream dos = new DEROutputStream();
            dos.putSequence(pkcs8);
            result = dos.toByteArray();
            dos.close();
            encoded = result;
        } catch (Exception ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Could not encode RSA private key!", ex);
            }
            LOG.warn("Could not encode RSA private key!: {}", ex.getMessage());
        }

        if (result == null) {
            return null;
        }
        return result.clone();
    }


    /**
     * Gets the key specification
     *
     * @return the key spec
     */
    public synchronized RSAPrivateKeySpec getKeySpec() {
        checkNotDestroyed();
        RSAPrivateCrtKeySpec result = keyspec;
        if (result == null) {
            // created from the encoded key: parse it on first access
            result = parseKeySpec(encoded);
            keyspec = result;
        }

        return result;
    }


    /**
     * @see java.security.interfaces.RSAPrivateKey#getPrivateExponent()
     */
    @Override
    public BigInteger getPrivateExponent() {
        checkNotDestroyed();
        RSAPrivateKeySpec spec = getKeySpec();
        if (spec == null) {
            return null;
        }
        
        return spec.getPrivateExponent();
    }


    /**
     * @see java.security.interfaces.RSAKey#getModulus()
     */
    @Override
    public BigInteger getModulus() {
        checkNotDestroyed();
        RSAPrivateKeySpec spec = getKeySpec();
        if (spec == null) {
            return null;
        }

        return spec.getModulus();
    }


    /**
     * Destroy the key: the encoded key bytes are overwritten with zeros and the key specification is removed.
     * The key can not be used anymore afterwards. The numbers of the key specification ({@link BigInteger})
     * can not be overwritten in Java, they are only released.
     *
     * @see javax.security.auth.Destroyable#destroy()
     */
    @Override
    public synchronized void destroy() {
        if (encoded != null) {
            Arrays.fill(encoded, (byte) 0);
            encoded = null;
        }
        keyspec = null;
        destroyed = true;
    }


    /**
     * @see javax.security.auth.Destroyable#isDestroyed()
     */
    @Override
    public boolean isDestroyed() {
        return destroyed;
    }


    /**
     * Check that the key is not destroyed
     *
     * @throws IllegalStateException if the key is destroyed
     */
    private void checkNotDestroyed() {
        if (destroyed) {
            throw new IllegalStateException("The private key is destroyed!");
        }
    }


    /**
     * Parse the key specification of a PKCS#8 encoded RSA private key.
     *
     * @param data the PKCS#8 encoded private key
     * @return the key specification or null if it can not be parsed
     */
    private static RSAPrivateCrtKeySpec parseKeySpec(byte[] data) {
        if (data == null) {
            return null;
        }

        try {
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PrivateKey privateKey = keyFactory.generatePrivate(new PKCS8EncodedKeySpec(data));
            return keyFactory.getKeySpec(privateKey, RSAPrivateCrtKeySpec.class);
        } catch (GeneralSecurityException | RuntimeException ex) {
            if (LOG.isDebugEnabled()) {
                LOG.debug("Could not parse RSA private key!", ex);
            }
            LOG.warn("Could not parse RSA private key!: {}", ex.getMessage());
            return null;
        }
    }


    /**
     * Converts a RSA private key into a DerValue
     *
     * @param a the private key
     * @return the DerValue
     */
    private static DERValue getDERValue(byte[] a) {
        return new DERValue((byte) 4, a);
    }


    /**
     * Converts a RSA private key into a DERValue
     *
     * @param keyspec the private key
     * @return the DerValue
     * @throws IOException In case of a data error
     */
    private static DERValue convert(RSAPrivateCrtKeySpec keyspec) throws IOException {
        keyspec.getModulus();
        keyspec.getPublicExponent();
        keyspec.getPrivateExponent();
        keyspec.getPrimeP();
        keyspec.getPrimeQ();
        keyspec.getPrimeExponentP();
        keyspec.getPrimeExponentQ();
        keyspec.getCrtCoefficient();
        DERValue[] rsastuff = new DERValue[9];

        rsastuff[0] = getTwoByteDerValue(new BigInteger("0"));
        rsastuff[1] = getTwoByteDerValue(keyspec.getModulus());
        rsastuff[2] = getTwoByteDerValue(keyspec.getPublicExponent());
        rsastuff[3] = getTwoByteDerValue(keyspec.getPrivateExponent());
        rsastuff[4] = getTwoByteDerValue(keyspec.getPrimeP());
        rsastuff[5] = getTwoByteDerValue(keyspec.getPrimeQ());
        rsastuff[6] = getTwoByteDerValue(keyspec.getPrimeExponentP());
        rsastuff[7] = getTwoByteDerValue(keyspec.getPrimeExponentQ());
        rsastuff[8] = getTwoByteDerValue(keyspec.getCrtCoefficient());

        DEROutputStream dos = new DEROutputStream();
        dos.putSequence(rsastuff);
        byte[] sequence = dos.toByteArray();
        dos.close();
        try {
            // the DERValue keeps its own copy
            return getDERValue(sequence);
        } finally {
            Arrays.fill(sequence, (byte) 0);
        }
    }


    /**
     * Create the initial DERValue
     *
     * @return the initiale DERValue
     * @throws IOException In case of a data error
     */
    private static DERValue init() throws IOException {
        DERValue[] a = new DERValue[2];
        a[0] = parse("1.2.840.113549.1.1.1");
        a[1] = new DERValue((byte) 5, new byte[0]);

        return parse(a);
    }

    
    /**
     * Parse the DERValue
     *
     * @param a the value to parse
     * @return the parse value
     * @throws IOException In case of a data error
     */
    private static DERValue parse(DERValue[] a) throws IOException {
        DEROutputStream dos = new DEROutputStream();
        dos.putSequence(a);
        DERInputStream dis = new DERInputStream(dos.toByteArray());
        dos.close();
        return dis.getDERValue();
    }

    
    /**
     * Parse the agiven object identifier
     *
     * @param id the identifier to parse
     * @return the parse identifier
     * @throws IOException In case of a data error
     */
    private static DERValue parse(String id) throws IOException {
        ObjectIdentifier oid = new ObjectIdentifier(id);
        DEROutputStream dos = new DEROutputStream();

        dos.putOID(oid);
        DERInputStream dis = new DERInputStream(dos.toByteArray());

        dos.close();
        return dis.getDERValue();
    }

    
    /**
     * Create a two byte DER value
     *
     * @param bi the integer
     * @return the value
     */
    private static DERValue getTwoByteDerValue(BigInteger bi) {
        byte[] value = bi.toByteArray();
        try {
            // the DERValue keeps its own copy
            return new DERValue((byte) 2, value);
        } finally {
            Arrays.fill(value, (byte) 0);
        }
    }
}
