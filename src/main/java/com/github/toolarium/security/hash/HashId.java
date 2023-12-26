/*
 * HashId.java
 *
 * Copyright by toolarium, all rights reserved.
 */
package com.github.toolarium.security.hash;

import com.github.toolarium.common.util.StringUtil;
import java.util.ArrayList;
import java.util.Collection;
import java.util.Iterator;
import java.util.List;
import java.util.stream.Collectors;


/**
 * HashId: A small Java class to generate YouTube-like hashes from one or many numbers, ported from javascript hashids.js by Ivan Akimov.
 * It was designed for web sites to use in URL shortening, tracking stuff, or making pages private (or at least unguessable).
 * This algorithm tries to satisfy the following requirements: Hashes must be unique and decryptable.
 * They should be able to contain more than one integer (so you can use them in complex or clustered systems).
 * You should be able to specify minimum hash length.
 * Hashes should not contain basic English curse words (since they are meant to appear in public places - like the URL).
 * Instead of showing items as 1, 2, or 3, you could show them as U6dc, u87U, and HMou. You don't have to store these hashes 
 * in the database, but can encrypt + decrypt on the fly.
 * All (long) integers need to be greater than or equal to zero.
 * 
 * @author patrick
 */
public final class HashId {
    private static final String DEFAULT_ALPHABET = "xcS4F6h89aUbideAI7tkynuopqrXCgTE5GBKHLMjfRsz";

    private static final int[] PRIMES = {2, 3, 5, 7, 11, 13, 17, 19, 23, 29, 31, 37, 41, 43 };
    private static final int[] SEPS_INDICES = {0, 4, 8, 12 };
    private String salt = "";
    private String alphabet = "";
    private int minHashLength;
    private List<Character> seps;
    private List<Character> guards;


    /**
     * Constructor for HashId
     * 
     * @param salt the salt
     * @param minHashLength the min length
     * @param alphabet the alphabet
     * @throws IllegalArgumentException In case of an invalid input
     */
    private HashId(String salt, int minHashLength, String alphabet) {
        if (alphabet == null || alphabet.isBlank()) {
            throw new IllegalArgumentException("alphabet must not be empty");
        }
        
        if (salt != null) {
            this.salt = salt;
        }
        
        if (minHashLength > 0) {
            this.minHashLength = minHashLength;
        }

        //this.alphabet = join(new LinkedHashSet<String>(StringUtil.getInstance().splitAsList(alphabet, "")), "");
        List<String> list = StringUtil.getInstance().splitAsList(alphabet, "");
        list = list.stream().distinct().collect(Collectors.toList());
        this.alphabet = join(list, "");
        if (this.alphabet.length() < 4) {
            throw new IllegalArgumentException("Alphabet must contain at least 4 unique characters.");
        }
        
        seps = new ArrayList<Character>();
        guards = new ArrayList<Character>();
        for (int prime : PRIMES) {
            if (prime < this.alphabet.length()) {
                char c = this.alphabet.charAt(prime - 1);
                seps.add(c);
                this.alphabet = this.alphabet.replace(c, ' ');
            }
        }

        for (int index : SEPS_INDICES) {
            if (index < seps.size()) {
                guards.add(seps.get(index));
                seps.remove(index);
            }
        }

        this.alphabet = consistentShuffle(this.alphabet.replaceAll(" ", ""), this.salt);
    }
    
    
    /**
     * Create a hash id class
     * 
     * @return the instance
     */
    public static HashId createHashId() {
        return new HashId("", 0, DEFAULT_ALPHABET);
    }

    
    /**
     * Create a hash id class
     * 
     * @param salt the salt
     * @return the instance
     */
    public static HashId createHashId(String salt) {
        return new HashId(salt, 0, DEFAULT_ALPHABET);
    }
    
    
    /**
     * Create a hash id class
     * 
     * @param salt the salt
     * @param minHashLength the min hash length
     * @return the instance
     */
    public static HashId createHashId(String salt, int minHashLength) {
        return new HashId(salt, minHashLength, DEFAULT_ALPHABET);
    }

    
    /**
     * Create a hash id class
     * 
     * @param salt the salt
     * @param minHashLength the min hash length
     * @param alphabet the alphabet
     * @return the instance
     */
    public static HashId createHashId(String salt, int minHashLength, String alphabet) {
        return new HashId(salt, minHashLength, alphabet);
    }

    
    /**
     * Get the salt
     * 
     * @return the salt
     */
    public String getSalt() {
        return salt;
    }

    
    /**
     * Get the alphabet
     * 
     * @return the alphabet
     */
    public String getAlphabet() {
        return alphabet;
    }

    
    /**
     * Get the min hash length
     * 
     * @return the min hash length
     */
    public int getMinHashLength() {
        return minHashLength;
    }

    
    /**
     * Encrypt
     * 
     * @param inputNumbers some numbers
     * @return the generated hash id
     */
    public String encrypt(long... inputNumbers) {
        long[] numbers = new long[inputNumbers.length];
        for (int i = 0; i < numbers.length; i++) {
            if (inputNumbers[i] < 0) {
                numbers[i] = -1 * inputNumbers[i];
            } else {
                numbers[i] = inputNumbers[i];
            }
        }

        return encode(numbers, alphabet, salt, minHashLength);
    }

    
    /**
     * Decrypt
     * 
     * @param hash the hash to decrypt
     * @return the decrypted hash
     */
    public long[] decrypt(String hash) {
        long[] inputNumbers = decode(hash);
        long[] numbers = new long[inputNumbers.length];

        for (int i = 0; i < inputNumbers.length; i++) {
            if (inputNumbers[i] < 0) {
                numbers[i] = -1 * inputNumbers[i];
            } else {
                numbers[i] = inputNumbers[i];
            }
        }

        return numbers;
    }

    
    /**
     * Encode
     * 
     * @param numbers the numbers
     * @param inputAlphabet the alphabet
     * @param inputSalt the salt
     * @param inputMinHashLength the min length
     * @return the hash
     */
    private String encode(long[] numbers, String inputAlphabet, String inputSalt, int inputMinHashLength) {
        String alphabet = inputAlphabet;
        String ret = "";
        String shuffeltSeps = consistentShuffle(join(seps, ""), join(numbers, ""));
        char lotteryChar = 0;

        for (int i = 0; i < numbers.length; i++) {
            if (i == 0) {
                String lotterySalt = join(numbers, "-");
                for (long number : numbers) {
                    lotterySalt += "-" + (number + 1) * 2;
                }
                
                String lottery = consistentShuffle(alphabet, lotterySalt);
                lotteryChar = lottery.charAt(0);
                ret += lotteryChar;

                alphabet = lotteryChar + alphabet.replaceAll(String.valueOf(lotteryChar), "");
            }

            alphabet = consistentShuffle(alphabet, (lotteryChar & 12345) + inputSalt);
            ret += hash(numbers[i], alphabet);

            if (i + 1 < numbers.length) {
                ret += shuffeltSeps.charAt((int) ((numbers[i] + i) % shuffeltSeps.length()));
            }
        }

        if (ret.length() < inputMinHashLength) {
            int firstIndex = 0;
            for (int i = 0; i < numbers.length; i++) {
                firstIndex += (i + 1) * numbers[i];
            }
            
            int guardIndex = firstIndex % guards.size();
            if (guardIndex >= 0) {
                char guard = guards.get(guardIndex);
                ret = guard + ret;
    
                if (ret.length() < inputMinHashLength) {
                    guardIndex = (guardIndex + ret.length()) % guards.size();
                    guard = guards.get(guardIndex);
                    ret += guard;
                }
            }
        }

        while (ret.length() < inputMinHashLength) {
            long[] padArray = new long[] {alphabet.charAt(1), alphabet.charAt(0) };
            String padLeft = encode(padArray, alphabet, inputSalt, 0);
            String padRight = encode(padArray, alphabet, join(padArray, ""), 0);

            ret = padLeft + ret + padRight;
            int excess = ret.length() - inputMinHashLength;
            if (excess > 0) {
                ret = ret.substring(excess / 2, excess / 2 + inputMinHashLength);
            }
            
            alphabet = consistentShuffle(alphabet, inputSalt + ret);
        }

        return ret;
    }
    
    
    /**
     * Decode
     * 
     * @param inputHash the input hash
     * @return the id's
     */
    private long[] decode(String inputHash) {
        String hash = inputHash;
        List<Long> ret = new ArrayList<Long>();
        String originalHash = hash;

        if (hash != null && !hash.isEmpty()) {
            String a = "";
            char lotteryChar = 0;

            for (char guard : guards) {
                hash = hash.replaceAll(String.valueOf(guard), " ");
            }
            
            String[] hashSplit = StringUtil.getInstance().splitAsArray(hash, " ");
            if (hashSplit.length == 3 || hashSplit.length == 2) {
                hash = hashSplit[1];
            } else {
                hash = hashSplit[0];
            }

            for (char sep : seps) {
                hash = hash.replaceAll(String.valueOf(sep), " ");
            }
            
            String[] hashArray = StringUtil.getInstance().splitAsArray(hash, " ");
            for (int i = 0; i < hashArray.length; i++) {
                String subHash = hashArray[i];

                if (subHash != null && !subHash.isEmpty()) {
                    if (i == 0) {
                        lotteryChar = hash.charAt(0);
                        subHash = subHash.substring(1);
                        a = lotteryChar + alphabet.replaceAll(String.valueOf(lotteryChar), "");
                    }
                }

                if (a.length() > 0) {
                    a = consistentShuffle(a, (lotteryChar & 12345) + salt);
                    ret.add(unhash(subHash, a));
                }
            }
        }

        long[] numbers = longListToPrimitiveArray(ret);
        if (!encrypt(numbers).equals(originalHash)) {
            return new long[0];
        }
        
        return numbers;
    }
    
    
    /**
     * Hash
     * 
     * @param inputNumber the input number
     * @param inputAlphabet the alphabet
     * @return the hash
     */
    private String hash(long inputNumber, String inputAlphabet) {
        long number = inputNumber;
        String hash = "";

        while (number > 0) {
            hash = inputAlphabet.charAt((int) (number % inputAlphabet.length())) + hash;
            number = number / inputAlphabet.length();
        }

        return hash;
    }

    
    /**
     * Unhash
     * 
     * @param hash the hash
     * @param inputAlphabet the alphabet
     * @return the result
     */
    private long unhash(String hash, String inputAlphabet) {
        long number = 0;

        for (int i = 0; i < hash.length(); i++) {
            int pos = inputAlphabet.indexOf(hash.charAt(i));
            number += pos * (long) Math.pow(inputAlphabet.length(), hash.length() - i - 1);
        }

        return number;
    }

    
    /**
     * Consistent shuffle
     * 
     * @param alphabet the alphabet 
     * @param inputSalt the input salt
     * @return the result
     */
    private static String consistentShuffle(String alphabet, String inputSalt) {
        String ret = "";
        String salt = inputSalt;

        if (!alphabet.isEmpty()) {
            if (salt == null || salt.isEmpty()) {
                salt = new String(new char[] {'\0' });
            }
            
            int[] sortingArray = new int[salt.length()];
            for (int i = 0; i < salt.length(); i++) {
                sortingArray[i] = salt.charAt(i);
            }

            for (int i = 0; i < sortingArray.length; i++) {
                boolean add = true;
                for (int k = i; k != sortingArray.length + i - 1; k++) {
                    int nextIndex = (k + 1) % sortingArray.length;

                    if (add) {
                        sortingArray[i] += sortingArray[nextIndex] + (k * i);
                    } else {
                        sortingArray[i] -= sortingArray[nextIndex];
                    }

                    add = !add;
                }

                sortingArray[i] = Math.abs(sortingArray[i]);
            }

            int i = 0;
            List<String> alphabetArray = charArrayToStringList(alphabet.toCharArray());
            while (alphabetArray.size() > 0) {
                int pos = sortingArray[i];
                if (pos >= alphabetArray.size()) {
                    pos %= alphabetArray.size();
                }
                
                ret += alphabetArray.get(pos);
                alphabetArray.remove(pos);
                i = ++i % sortingArray.length;
            }
        }

        return ret;
    }
 
    
    /**
     * Convert long list into a primitive array 
     * 
     * @param longList the long list
     * @return the primitive array
     */
    private static long[] longListToPrimitiveArray(List<Long> longList) {
        long[] longArr = new long[longList.size()];
        int i = 0;

        for (long l : longList) {
            longArr[i++] = l;
        }

        return longArr;
    }

    
    /**
     * Convert a char array into a string list
     * 
     * @param chars the char array
     * @return the string list
     */
    private static List<String> charArrayToStringList(char[] chars) {
        ArrayList<String> list = new ArrayList<String>(chars.length);
        for (char c : chars) {
            list.add(String.valueOf(c));
        }
        
        return list;
    }

    
    /**
     * Join long array with delimiter
     * 
     * @param longList the long value array
     * @param delimiter the delimiter
     * @return the string
     */
    private static String join(long[] longList, String delimiter) {
        ArrayList<String> strList = new ArrayList<String>(longList.length);
        for (long l : longList) {
            if (l < 0) {
                strList.add(String.valueOf(l));
            } else { 
                strList.add(String.valueOf(l));
            }
        }

        return join(strList, delimiter);
    }

    
    /**
     * Join collection with delimiter
     * 
     * @param c the collection
     * @param delimiter the delimiter
     * @return the string
     */
    private static String join(Collection<?> c, String delimiter) {
        Iterator<?> iter = c.iterator();
        if (iter.hasNext()) {
            StringBuilder builder = new StringBuilder(c.size());
            builder.append(iter.next());
            while (iter.hasNext()) {
                builder.append(delimiter);
                builder.append(iter.next());
            }

            return builder.toString();
        }

        return "";
    }
}
