/*
 * SignatureUtil.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.signature;

import com.github.toolarium.security.pki.util.PKIUtil;
import com.github.toolarium.security.util.CryptUtil;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * This class implements a simple interface to sign data and verify the signed data. 
 * The class works with the standard API of java and use public and private keys.
 * 
 * @author patrick
 */
public final class SignatureUtil {
    private static final Logger LOG = LoggerFactory.getLogger(SignatureUtil.class);

    
    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     *
     * @author patrick
     */
    private static class HOLDER {
        static final SignatureUtil INSTANCE = new SignatureUtil();
    }
    

    /**
     * Constructor
     */
    private SignatureUtil() {
        // NOP
    }

    
    /**
     * Get the instance
     *
     * @return the instance
     */
    public static SignatureUtil getInstance() {
        return HOLDER.INSTANCE;
    }


    /**
     * Verify a signed data.
     * 
     * @param algorithm the algorithm like: SHA1withRSA, SHA1withDSA, RSA...
     * @param publicKey the public key
     * @param dataToVerify the data to verify the signature
     * @param dataToCompareWith the data to compare with the signed data
     * @return true if the verification of the response is identical.
     * @throws GeneralSecurityException in case of error
     */
    public boolean verify(String algorithm, PublicKey publicKey, byte[] dataToVerify, byte[] dataToCompareWith) throws GeneralSecurityException {
        return verify(null, algorithm, publicKey, dataToVerify, dataToCompareWith);
    }


    /**
     * Verify a signed data.
     * 
     * @param provider the provider
     * @param algorithm the algorithm like: SHA1withRSA, SHA1withDSA, RSA...
     * @param publicKey the public key
     * @param dataToVerify the data to verify the signature
     * @param dataToCompareWith the data to compare with the signed data
     * @return true if the verification of the response is identical.
     * @throws GeneralSecurityException in case of error
     */
    public boolean verify(String provider, String algorithm, PublicKey publicKey, byte[] dataToVerify, byte[] dataToCompareWith) throws GeneralSecurityException {
        if (LOG.isInfoEnabled()) {
            LOG.info("Validate response (" + CryptUtil.getInstance().getAlgorithmMessage(provider, algorithm) + ")...");
        }

        if (algorithm == null) {
            throw new GeneralSecurityException("Invalid algorithm!");
        }
        
        if (publicKey == null) {
            throw new GeneralSecurityException("Invalid PrivateKey!");
        }
        
        if (dataToVerify == null) {
            throw new GeneralSecurityException("Invalid data to verify!");
        }
        
        if (dataToCompareWith == null) {
            throw new GeneralSecurityException("Invalid data to compare!");
        }

        if (LOG.isDebugEnabled()) {
            PKIUtil.getInstance().processPublicKeyInfo(LOG::debug, null, publicKey);
            LOG.debug("Getting signature verification object instance.");
        }

        Signature verifier = null;
        if (provider != null && provider.trim().length() > 0) {
            verifier = Signature.getInstance(algorithm, provider.trim());
        } else {
            verifier = Signature.getInstance(algorithm);
        }
        
        if (verifier == null) {
            throw new GeneralSecurityException("Could not create verifier object!");
        }
            
        // Initialise the decryption object. This call will set up verifier to perform signature verification.
        if (LOG.isDebugEnabled()) {
            LOG.debug("Initializing verification object with public key.");
        }
        verifier.initVerify(publicKey);

        // Now, pass in the data to be verified. The call to update() will produce a message digest of all the data passed in via any update() calls.
        if (LOG.isDebugEnabled()) {
            LOG.debug("Processing response data to be verified.");
        }
        verifier.update(dataToVerify);

        // Now that we have passed in all of the data to decrypt we will call verify(). verify() will decrypt the signature produced earlier, and compare 
        // the message digest within to the one generated during calls to update().
        if (LOG.isDebugEnabled()) {
            LOG.debug("Verifying against the challenge ...");
        }
        
        final boolean result = verifier.verify(dataToCompareWith);
        if (result) {
            if (LOG.isInfoEnabled()) {
                LOG.info("Signature successful verified!");
            }
        } else {
            LOG.warn("Invalid signature!");
        }

        return result;
    }


    /**
     * Sign data with the given algorithm and private key.
     * 
     * @param algorithm the algorithm like: SHA1withRSA, SHA1withDSA, RSA...
     * @param privateKey the private key
     * @param data the data to sign
     * @return the signed response
     * @throws GeneralSecurityException in case of error
     */
    public byte[] sign(String algorithm, PrivateKey privateKey, byte[] data) throws GeneralSecurityException {
        return sign(null, algorithm, privateKey, data);
    }

    
    /**
     * Sign data with the given algorithm and private key.
     * 
     * @param provider the provider
     * @param algorithm the algorithm like: SHA1withRSA, SHA1withDSA, RSA...
     * @param privateKey the private key
     * @param data the data to sign
     * @return the signed response
     * @throws GeneralSecurityException in case of error
     */
    public byte[] sign(String provider, String algorithm, PrivateKey privateKey, byte[] data) throws GeneralSecurityException {
        if (LOG.isInfoEnabled()) {
            LOG.info("Sign data (" + CryptUtil.getInstance().getAlgorithmMessage(provider, algorithm) + ")...");
        }
        
        if (algorithm == null) {
            throw new GeneralSecurityException("Invalid algorithm!");
        }
        
        if (privateKey == null) {
            throw new GeneralSecurityException("Invalid PrivateKey!");
        }
        
        if (data == null) {
            throw new GeneralSecurityException("Invalid data!");
        }
        
        if (LOG.isDebugEnabled()) {
            PKIUtil.getInstance().processPrivateKeyInfo(LOG::debug, null, privateKey);
            LOG.debug("Getting signature object instance.");
        }
        
        // Get a Signature object for to generate the internal message digest. The JCE specifies that RSA encryption use PKCS #1 Block type 02 padding, by default.
        Signature signer;
        if (provider != null && provider.trim().length() > 0) {
            signer = Signature.getInstance(algorithm, provider.trim());
        } else {
            signer = Signature.getInstance(algorithm);
        }
        
        if (signer == null) {
            throw new GeneralSecurityException("Could not create signer object!");
        }
        
        // Initialize the Signature object. This call will set up the signer to perform signatures.
        if (LOG.isDebugEnabled()) {
            LOG.debug("Initializing signature object with private key.");
        }
        signer.initSign(privateKey);

        // Now, pass in the data to be signed. The call to update() will process the data passed in. Nothing will be output until the call to sign().
        if (LOG.isDebugEnabled()) {
            LOG.debug("Processing data to be signed.");
        }
        signer.update(data);

        // Now that we have passed in all of the data to encrypt we will call sign(). sign() will take the message digest of the data
        // passed in via update() and encrypt that digest.
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signing the data.");
        }
        
        final byte[] result = signer.sign();
        if (LOG.isInfoEnabled()) {
            LOG.info("Data successful signed.");
        }
        return result;
    }
}
