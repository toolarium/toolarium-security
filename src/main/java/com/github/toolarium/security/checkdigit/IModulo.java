/*
 * IModulo.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.checkdigit;

/**
 * Defines the modulo digest api.
 * 
 * @author patrick
 */
public interface IModulo<T> {
    
    /**
     * Validate a number if modulo is valid
     * 
     * @param data the number to be checked
     * @return true if it is valid; otherwise false
     */
    boolean validate(String data);
    
    /**
     * Calculate the modulo of the given string.
     * 
     * @param data the data to parse
     * @return the modulo result
     */
    T createCheckDigit(String data);
    
}
