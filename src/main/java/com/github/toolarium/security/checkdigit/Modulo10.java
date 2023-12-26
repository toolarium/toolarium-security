/*
 * Modulo10.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.checkdigit;

/**
 * Implements the modulo 10 also known as LUHN.
 * 
 * @author patrick
 */
public final class Modulo10 extends AbstractModulo<Long> {

    /**
     * Private class, the only instance of the singelton which will be created by accessing the holder class.
     *
     * @author patrick
     */
    private static class HOLDER {
        static final Modulo10 INSTANCE = new Modulo10();
    }

    
    /**
     * Constructor
     */
    private Modulo10() {
        // NOP
    }

    
    /**
     * Get the instance
     *
     * @return the instance
     */
    public static Modulo10 getInstance() {
        return HOLDER.INSTANCE;
    }


    /**
     * Calculate the modulo 10 of the given string which contains numbers 
     * e.g. <code>4563 9601 2200 199</code> or <code>446-667-65</code>
     * 
     * @see com.github.toolarium.security.checkdigit.IModulo#createCheckDigit(java.lang.String)
     */
    @Override
    public Long createCheckDigit(String data) {
        if (data == null || data.isBlank()) {
            throw new IllegalArgumentException("Invalid numbers!");
        }
        
        long number = calculateModulo(data + "0");
        long result = number % 10;
        if (result == 0) {
            return Long.valueOf(0);
        }
        
        return 10 - (number % 10);
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

        for (int i = 0; i < length; i++) {
            // get digits in reverse order
            int digit = digits[length - i - 1];

            // if current digit is not checksum AND mod2 equals parity then multiply with 2
            if ((i > 0) && (i % 2 != 0)) {
                digit *= 2;
            }

            if (digit > 9) {
                sum += digit - 9;
            } else {
                sum += digit;
            }
        }

        return sum;
    }
}
