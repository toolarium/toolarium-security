/*
 * JsonSignatureUtil.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.signature;

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

    // Derived from the same constants used in sign() — guaranteed to match the produced format
    private static final String REQUEST_PREFIX = OPEN_BRACE + NL + SPACE + QUOTATION_MARKS + "request" + QUOTATION_MARKS + COLON + SPACE;
    private static final String SIGNATURE_INFIX = COME + NL + SPACE + QUOTATION_MARKS + "signature" + QUOTATION_MARKS + COLON + QUOTATION_MARKS;
    private static final String SIGNATURE_SUFFIX = QUOTATION_MARKS + NL + ENDING_BRACE;



    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     *
     * @author patrick
     */
    private static final class HOLDER {
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
            LOG.debug("Signature generated (" + signature.length() + " chars)");
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
        final String json = validateJsonInput(requestToVerify);

        // Verify the exact wrapper structure produced by sign()
        if (!json.startsWith(REQUEST_PREFIX)) {
            throw new IllegalArgumentException("Invalid JSON: missing request field");
        }
        if (!json.endsWith(SIGNATURE_SUFFIX)) {
            throw new IllegalArgumentException("Invalid JSON: missing signature field");
        }

        // lastIndexOf is safe here: the signature value is base64 (A-Za-z0-9+/=) which cannot
        // contain the SIGNATURE_INFIX characters, so SIGNATURE_INFIX cannot appear after the real field
        final int sigInfixIdx = json.lastIndexOf(SIGNATURE_INFIX);
        if (sigInfixIdx < REQUEST_PREFIX.length()) {
            throw new IllegalArgumentException("Invalid JSON: missing signature field");
        }

        // Extract the original request content (what was signed) and the signature value
        final String requestContent = json.substring(REQUEST_PREFIX.length(), sigInfixIdx);
        final String signature = json.substring(sigInfixIdx + SIGNATURE_INFIX.length(), json.length() - SIGNATURE_SUFFIX.length());

        // Reject any content injected after the signature value (must be pure base64)
        if (!signature.matches("[A-Za-z0-9+/=]+")) {
            throw new IllegalArgumentException("Invalid JSON: malformed signature encoding");
        }

        if (LOG.isDebugEnabled()) {
            LOG.debug("Parsed signature [" + signature + "]");
            LOG.debug("Parsed request [" + requestContent + "]");
        }

        final byte[] rawContent = requestContent.getBytes(StandardCharsets.UTF_8);
        final byte[] signatureToVerify = Base64.getDecoder().decode(signature.getBytes());
        return SignatureUtil.getInstance().verify(provider, signatureAlgorithm, publicKey, rawContent, signatureToVerify);
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
        if (!json.startsWith(OPEN_BRACE) || !json.endsWith(ENDING_BRACE)) {
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
