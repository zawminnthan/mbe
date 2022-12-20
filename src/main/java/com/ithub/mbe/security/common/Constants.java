/*
 * Copyright &copy MSI Global Pte Ltd (Singapore) 2022. All rights reserved.
 * The contents of this document are property of MSI Global Pte Ltd (Singapore).
 * No part of this work may be reproduced or transmitted in any form or by any means,
 * except as permitted by written license agreement with the MSI Global Pte Ltd
 * (Singapore).
 */
package com.ithub.mbe.security.common;

/**
 * Constants
 *
 * @author Zaw
 * @since 1.0
 * <p>
 * <pre>
 * Revision History:
 * Version  Date            Author          Changes
 * ------------------------------------------------------------------------------------------------------------------------
 * 1.0      21/9/2022     Zaw           Initial Coding
 *
 * </pre>
 */
public class Constants {

    /**
     * SIGNING_ALGORITHM
     */
    public static final String SIGNING_ALGORITHM= "SHA256withRSA";

    /**
     * RSA
     */
    public static final String RSA = "RSA";

    /**
     * AES
     */
    public static final String AES = "AES";

    /**
     * AES_CBC
     */
    public static final String AES_CBC = "AES/CBC/PKCS5Padding";

    /**
     * KEY_SIZE
     */
    public static final int KEY_SIZE = 2048;

    /**
     * SHA256
     */
    public static final String SHA256 = "SHA-256";

    /**
     * RSA_PRIVATE_KEY
     */
    public static final String RSA_PRIVATE_KEY = "RSA PRIVATE KEY";

    /**
     * RSA_PUBLIC_KEY
     */
    public static final String RSA_PUBLIC_KEY = "RSA PUBLIC KEY";

    /**
     * PUBLIC_KEY
     */
    public static final String PUBLIC_KEY = "PUBLIC KEY";

    // Public Key
    public static final String PEM_PUBLIC_START = "-----BEGIN PUBLIC KEY-----";
    public static final String PEM_PUBLIC_END = "-----END PUBLIC KEY-----";

    // PKCS#8 format
    public static final String PEM_PRIVATE_START = "-----BEGIN PRIVATE KEY-----";
    public static final String PEM_PRIVATE_END = "-----END PRIVATE KEY-----";

    // PKCS#1 format
    public static final String PEM_RSA_PRIVATE_START = "-----BEGIN RSA PRIVATE KEY-----";
    public static final String PEM_RSA_PRIVATE_END = "-----END RSA PRIVATE KEY-----";

    public static final String PKCS_1_PEM_HEADER = "-----BEGIN RSA PRIVATE KEY-----";
    public static final String PKCS_1_PEM_FOOTER = "-----END RSA PRIVATE KEY-----";

    public static final String PKCS_8_PEM_HEADER = "-----BEGIN PRIVATE KEY-----";
    public static final String PKCS_8_PEM_FOOTER = "-----END PRIVATE KEY-----";

    /**
     * IV
     */
    public static final byte[] IV = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

    /**
     * SALT
     */
    public static final byte[] SALT = {0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0};

}
