/*
 * Modulo11.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.checkdigit;

/**
 * Implements the modulo 11.
 * 
 * @author patrick
 */
public final class Modulo11 extends AbstractModulo<String> {
    
    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     *
     * @author patrick
     */
    private static class HOLDER {
        static final Modulo11 INSTANCE = new Modulo11();
    }

    
    /**
     * Constructor
     */
    private Modulo11() {
        // NOP
    }

    /**
     * Get the instance
     *
     * @return the instance
     */
    public static Modulo11 getInstance() {
        return HOLDER.INSTANCE;
    }


    /**
     * Calculate the modulo 11 of the given string which contains numbers 
     * e.g. <code>4563 9601 2200 199</code> or <code>446-667-65</code>
     * 
     * @see com.github.toolarium.security.checkdigit.IModulo#createCheckDigit(java.lang.String)
     */
    @Override
    public String createCheckDigit(String data) {
        if (data == null || data.isBlank()) {
            throw new IllegalArgumentException("Invalid numbers!");
        }

        long number = calculateModulo(data);
        long result = number % 11;
        if (result == 0) {
            return "0";
        }
        
        if (result == 1) {
            return "X";
        }

        return (Long.valueOf(11 - result)).toString();
    }


    /**
     * @see com.github.toolarium.security.checkdigit.AbstractModulo#calculateSum(java.lang.Integer[])
     */
    @Override
    protected long calculateSum(Integer[] digits) {
        if (digits == null || digits.length == 0) {
            throw new IllegalArgumentException("Invalid numbers!");
        }
        
        long sum = 0;
        int length = digits.length;

        for (int i = 1; i <= length; i++) {
            // get digits in reverse order
            int digit = digits[i - 1];
            sum += (11 - i) * digit;
        }

        return sum;
    }
}
