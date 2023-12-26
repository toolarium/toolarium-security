/*
 * JsonSignatureUtil.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.signature;

import com.github.toolarium.common.util.StringUtil;
import java.nio.charset.StandardCharsets;
import java.security.GeneralSecurityException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;


/**
 * JSON signature based on https://global.alipay.com/docs/ac/gr/signature#d2e38597
 * 
 * @author patrick
 */
public final class JsonSignatureUtil {
    private static final Logger LOG = LoggerFactory.getLogger(JsonSignatureUtil.class);
    private static final String OPEN_BRACE = "{";
    private static final String ENDING_BRACE = "}";
    private static final String QUOTATION_MARKS = "\"";
    private static final String COLON = ":";
    private static final String COME = ",";
    private static final String NL = "\n";
    private static final String SPACE = " ";

    
    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     *
     * @author patrick
     */
    private static class HOLDER {
        static final JsonSignatureUtil INSTANCE = new JsonSignatureUtil();
    }

    
    /**
     * Constructor
     */
    private JsonSignatureUtil() {
        // NOP
    }

    
    /**
     * Get the instance
     *
     * @return the instance
     */
    public static JsonSignatureUtil getInstance() {
        return HOLDER.INSTANCE;
    }


    /**
     * Sign a json 
     *
     * @param provider the provider
     * @param signatureAlgorithm the signature algorithm like: SHA1withRSA, SHA1withDSA, RSA...
     * @param privateKey the private key
     * @param inputJson the input json
     * @return the signed json
     * @throws GeneralSecurityException In case of a security exception
     * @throws IllegalArgumentException In case of invalid input
     */
    public String sign(String provider, String signatureAlgorithm, PrivateKey privateKey, String inputJson) throws GeneralSecurityException {
        final String json = validateJsonInput(inputJson);
        if (LOG.isDebugEnabled()) {
            LOG.debug("JSON request to sign [" + json + "]");
        }

        // raw content to sign and test
        final byte[] rawContent = json.getBytes(StandardCharsets.UTF_8);

        // create signature
        final byte[] rawSignature = SignatureUtil.getInstance().sign(provider, signatureAlgorithm, privateKey, rawContent);
        final String signature = new String(Base64.getEncoder().encode(rawSignature));
        
        if (LOG.isDebugEnabled()) {
            LOG.debug("Signature: " + signature);
        }
        
        StringBuilder result = new StringBuilder()
                .append(OPEN_BRACE).append(NL).append(SPACE)
                    .append(QUOTATION_MARKS).append("request").append(QUOTATION_MARKS).append(COLON).append(SPACE)
                    .append(json).append(COME).append(NL)
                    .append(SPACE).append(QUOTATION_MARKS).append("signature").append(QUOTATION_MARKS).append(COLON).append(QUOTATION_MARKS).append(signature).append(QUOTATION_MARKS).append(NL)
                .append(ENDING_BRACE);

        if (LOG.isDebugEnabled()) {
            LOG.debug("Signed JSON request [" + result + "]");
        }

        return result.toString();
    }


    /**
     * Verify signed json content
     *
     * @param provider the provider
     * @param signatureAlgorithm the signature algorithm like: SHA1withRSA, SHA1withDSA, RSA...
     * @param publicKey the public key
     * @param requestToVerify the request to verify
     * @return true if the signature match with the signed request
     * @throws GeneralSecurityException In case of a security exception
     * @throws IllegalArgumentException In case of invalid input
     */
    public boolean verify(String provider, String signatureAlgorithm, PublicKey publicKey, String requestToVerify) throws GeneralSecurityException {
        String json = validateJsonInput(requestToVerify);
        json = json.substring(1, json.length() - 1); // cut braces
        json = trimStartingNewlines(trimEndingNewlines(json)); // newlines
        
        int idx = json.indexOf("request");
        if (idx < 0) {
            throw new IllegalArgumentException("Invalid JSON!");
        }
        
        json = json.substring(idx + "request".length());
        json = StringUtil.getInstance().trimLeft(json, QUOTATION_MARKS.toCharArray()[0]);
        json = StringUtil.getInstance().trimLeft(json, COLON.toCharArray()[0]);
        
        idx = json.lastIndexOf("signature");
        if (idx < 0) {
            throw new IllegalArgumentException("Invalid JSON!");
        }
        
        String signature = StringUtil.getInstance().trimLeft(json.substring(idx + "signature".length()), QUOTATION_MARKS.toCharArray()[0]);
        signature = StringUtil.getInstance().trimLeft(signature, QUOTATION_MARKS.toCharArray()[0]);
        signature = StringUtil.getInstance().trimLeft(signature, COLON.toCharArray()[0]);
        signature = StringUtil.getInstance().trimLeft(signature, QUOTATION_MARKS.toCharArray()[0]);
        signature = StringUtil.getInstance().trimRight(signature, QUOTATION_MARKS.toCharArray()[0]);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Pasred signature [" + signature + "]");
        }

        json = StringUtil.getInstance().trimRight(json.substring(0, idx), QUOTATION_MARKS.toCharArray()[0]);
        json = trimEndingNewlines(json);
        json = StringUtil.getInstance().trimRight(json, COME.toCharArray()[0]);
        if (LOG.isDebugEnabled()) {
            LOG.debug("Parsed request [" + json + "]");
        }

        // raw content to sign and test
        final byte[] rawContent = json.getBytes(StandardCharsets.UTF_8);

        // decode signature and compare
        final byte[] sigantureToVerify = Base64.getDecoder().decode(signature.getBytes());
        boolean result = SignatureUtil.getInstance().verify(provider, signatureAlgorithm, publicKey, rawContent, sigantureToVerify);
        return result;
    }

    
    /**
     * Validate json input
     * 
     * @param inputJson the json input
     * @return the verified input
     * @throws IllegalArgumentException In case of invalid input
     */
    private String validateJsonInput(String inputJson) {
        if (inputJson == null || inputJson.isBlank()) {
            throw new IllegalArgumentException("Invalid JSON!");
        }

        final String json = trimStartingNewlines(trimEndingNewlines(inputJson));
        if (!json.startsWith(OPEN_BRACE) && !json.endsWith(ENDING_BRACE)) {
            throw new IllegalArgumentException("Invalid JSON!");
        }
        return json;
    }
   
    
    /**
     * Trim starting newlines
     *
     * @param input the input
     * @return the prepared input
     */
    private String trimStartingNewlines(String input) {
        if (input == null) {
            return input;
        }
        
        String json = input.trim();
        while (!json.isEmpty() && (json.startsWith("\r") || json.startsWith(NL))) {
            json = json.substring(1);
        }
        
        return json;
    }


    /**
     * Trim ending newlines
     *
     * @param input the input
     * @return the prepared input
     */
    private String trimEndingNewlines(String input) {
        if (input == null) {
            return input;
        }
        
        String json = input.trim();
        while (!json.isEmpty() && (json.endsWith("\r") || json.endsWith(NL))) {
            json = json.substring(0, json.length() - 1);
        }
        
        return json;
    }
}
