/*
 * Copyright &copy MSI Global Pte Ltd (Singapore) 2022. All rights reserved.
 * The contents of this document are property of MSI Global Pte Ltd (Singapore).
 * No part of this work may be reproduced or transmitted in any form or by any means,
 * except as permitted by written license agreement with the MSI Global Pte Ltd
 * (Singapore).
 */
package com.ithub.mbe.security.vo;

import org.bouncycastle.util.io.pem.PemObject;
import org.bouncycastle.util.io.pem.PemWriter;

import java.io.FileNotFoundException;
import java.io.FileOutputStream;
import java.io.IOException;
import java.io.OutputStreamWriter;
import java.security.Key;

/**
 * PemFile
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
public class PemFile {

    /**
     * pemObject
     */
    private PemObject pemObject;

    /**
     *
     * @param key
     * @param description
     */
    public PemFile(Key key, String description) {
        this.pemObject = new PemObject(description, key.getEncoded());
    }

    /**
     *
     * @param filename
     * @throws FileNotFoundException
     * @throws IOException
     */
    public void write(String filename) throws FileNotFoundException, IOException {
        PemWriter pemWriter = new PemWriter(new OutputStreamWriter(new FileOutputStream(filename)));
        try {
            pemWriter.writeObject(this.pemObject);
        } finally {
            pemWriter.close();
        }
    }
}
