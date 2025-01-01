/*
 * JavaSecurityTester.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.test;

import java.security.NoSuchAlgorithmException;
import java.security.SecureRandom;
import java.time.Instant;
import javax.crypto.Cipher;
import javax.crypto.KeyGenerator;
import javax.crypto.SecretKey;


/**
 * Test the egd
 * 
 * @author patrick
 */
public final class JavaSecurityTester {
    public static final double NANOSECS = 1000000000.0;
    /** Represents the AES algorithm as string */
    public static final String ALGORITHM_AES = "AES";

    
    /**
     * Constructor for JavaSecurityEgdTester
     */
    private JavaSecurityTester() {
        // NOP
    }

    
    /**
     * The main class 
     *
     * @param args the arguments
     */
    public static void main(String[] args) {
        print("Java Security Tester: " + Instant.now());
        testStrongEncryption();
        testEdg();
    }

    
    /**
     * Test strong encryption
     */
    private static void testStrongEncryption() {
        // try to get access to strong encryption part
        try {
            final KeyGenerator keyGen = KeyGenerator.getInstance(ALGORITHM_AES);
            keyGen.init(256);
            final SecretKey key = keyGen.generateKey();
            final Cipher testCipher = Cipher.getInstance(ALGORITHM_AES);
            testCipher.init(Cipher.ENCRYPT_MODE, key);
            print("> Strong encryption is enabled.");
        } catch (Exception e) {
            print("> Strong encryption is disabled.");
        }
    }

    
    /**
     * Test secure random (edg)
     */
    private static void testEdg() {
        final long start = System.nanoTime();
        byte[] randomBytes = new byte[256];

        try {
            SecureRandom secureRandom = SecureRandom.getInstanceStrong();
            secureRandom.nextBytes(randomBytes);
            
            final double duration = (System.nanoTime() - start) / NANOSECS;
            print("> Secure random, java.security.egd = " + System.getProperty("java.security.egd") + " took " + duration + " seconds and used the " + secureRandom.getAlgorithm() + " algorithm.");
        } catch (NoSuchAlgorithmException e) {
            print("> Secure random, could not get algorithm: " + e.getMessage());
        }
    }

    
    /**
     * Print to standard out
     *
     * @param msg the message
     */
    private static void print(String msg) {
        System.out.println(msg); // CHECKSTYLE IGNORE THIS LINE
    }
}