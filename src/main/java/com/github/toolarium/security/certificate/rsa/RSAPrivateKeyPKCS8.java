/*
 * RSAPrivateKeyPKCS8.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.certificate.rsa;

import com.github.toolarium.security.certificate.rsa.der.DERInputStream;
import com.github.toolarium.security.certificate.rsa.der.DEROutputStream;
import com.github.toolarium.security.certificate.rsa.der.DERValue;
import com.github.toolarium.security.certificate.rsa.der.ObjectIdentifier;
import java.io.IOException;
import java.math.BigInteger;
import java.security.interfaces.RSAPrivateKey;
import java.security.spec.InvalidKeySpecException;
import java.security.spec.RSAPrivateCrtKeySpec;
import java.security.spec.RSAPrivateKeySpec;
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


    /**
     * Default constructor for RSAPrivateKeyPKCS8
     * 
     * @param encoded the private key as byte array
     */
    public RSAPrivateKeyPKCS8(byte[] encoded) {
        this.encoded = encoded;
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
        getEncoded();

        try {
            DERInputStream dis = new DERInputStream(encoded);
            DERValue[] derseq = dis.getSequence(3);
            
            if (!BigInteger.ZERO.equals(derseq[0].getInteger().toBigInteger())) {
                throw new InvalidKeySpecException("Bad DER sequence");
            }
        } catch (IOException e) {
            throw new InvalidKeySpecException(e.getMessage());
        }

        return;
    }

    
    /**
     * @see java.security.Key#getEncoded()
     */
    @Override
    public byte[] getEncoded() {
        if (encoded != null) {
            return encoded;
        }

        try {
            DERValue[] pkcs8 = new DERValue[3];
            pkcs8[0] = getTwoByteDerValue(new BigInteger("0"));
            pkcs8[1] = init();
            pkcs8[2] = convert(keyspec);

            DEROutputStream dos = new DEROutputStream();
            dos.putSequence(pkcs8);
            encoded = dos.toByteArray();
            dos.close();
        } catch (Exception ex) {
            LOG.warn("Could not encode RSA private key!", ex);
        }

        return encoded;
    }


    /**
     * Gets the key specification
     *
     * @return the key spec
     */
    public RSAPrivateKeySpec getKeySpec() {
        if (keyspec == null) {
            getEncoded();
        }

        return keyspec;
    }


    /**
     * @see java.security.interfaces.RSAPrivateKey#getPrivateExponent()
     */
    @Override
    public BigInteger getPrivateExponent() {
        if (keyspec == null) {
            return null;
        }
        
        return getKeySpec().getPrivateExponent();
    }


    /**
     * @see java.security.interfaces.RSAKey#getModulus()
     */
    @Override
    public BigInteger getModulus() {
        if (keyspec == null) {
            return null;
        }

        return getKeySpec().getModulus();
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
        DERValue sequence = parse(rsastuff);

        return getDERValue(sequence.toByteArray());
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
        return new DERValue((byte) 2, bi.toByteArray());
    }
}
