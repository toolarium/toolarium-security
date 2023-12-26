/*
 * AbstractModulo.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.checkdigit;


import java.util.ArrayList;
import java.util.List;


/**
 * Implements the base class of modulo calculation
 *  
 * @author patrick
 */
public abstract class AbstractModulo<T> implements IModulo<T> {

    /**
     * @see com.github.toolarium.security.checkdigit.IModulo#validate(java.lang.String)
     */
    @Override
    public boolean validate(String data) {
        if (data == null || data.isBlank()) {
            throw new IllegalArgumentException("Invalid number");
        }

        String orgData = data.trim();
        String dataToTest = orgData.substring(0, orgData.length() - 1);
        String modulo = "" + createCheckDigit(dataToTest);
        if (modulo.equals(orgData.substring(orgData.length() - 1))) {
            return true;
        }

        return false;
    }

    
    /**
     * Calculate the modulo sum
     * 
     * @param digits the integer digits
     * @return the sum
     */
    protected abstract long calculateSum(Integer[] digits);    
    
    
    /**
     * Calculate the modulo of the given string .
     * 
     * @param data the data to parse
     * @return the modulo result
     * @throws IllegalArgumentException In case of an invalid input
     */
    protected long calculateModulo(String data) {
        if (data == null || data.isBlank()) {
            throw new IllegalArgumentException("Invalid numbers!");
        }

        Integer[] digits = parseString(data);
        return calculateSum(digits);
    }
    
    
    /**
     * Parse the given string
     * 
     * @param inputData the data to parse
     * @return the parsed number
     * @throws IllegalArgumentException In case of an invalid input
     */
    protected Integer[] parseString(String inputData) {
        if (inputData == null || inputData.isBlank()) {
            throw new IllegalArgumentException("Invalid numbers!");
        }
        
        String data = inputData.trim();
        List<Integer> digitList = new ArrayList<Integer>();
        for (Character c : data.toCharArray()) {
            if (Character.isDigit(c)) {
                digitList.add(Character.getNumericValue(c));
            }
        }

        if (digitList == null || digitList.size() == 0) {
            throw new IllegalArgumentException("Invalid numbers: " + data);
        }
        
        Integer[] digits = new Integer[digitList.size()];
        digitList.toArray(digits);
        return digits;
    }
}
