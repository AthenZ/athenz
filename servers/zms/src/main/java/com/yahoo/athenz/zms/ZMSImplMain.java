/**
 * Copyright 2017 Yahoo Holdings Inc.
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
package com.yahoo.athenz.zms;

import java.io.BufferedReader;
import java.io.FileReader;
import java.io.IOException;
import java.util.Arrays;

import com.yahoo.athenz.auth.util.Crypto;

public class ZMSImplMain {
    private static final String AUDITREF = "Server bootstrap: instance private key registration";
    private static final ZMSImpl ZMS = new ZMSImpl();

    public static void main(String[] args) {
        System.out.println(Arrays.toString(args));
        if (args.length != 5) {
            System.out.println("does not meet argument requirement.");
            System.exit(1);
        }
        String command = args[0];
        try {
            switch (command.toLowerCase()) {
            case "put-public-key":
                putPublicKey(args);
                break;
            case "delete-public-key":
                deletePublicKey(args);
                break;
            default: 
                break;
            }
        } catch (Throwable e) {
            System.out.println(e.getMessage());
            System.exit(1);
        }
        System.exit(0);
    }
    
    private static PublicKeyEntry putPublicKey(String[] params) {
        String domainName = params[1];
        String serviceName = params[2];
        String keyId = params[3];
        String publicKeyFileName = params[4];
        String publicKey = null;
        
        if (null != publicKeyFileName && !publicKeyFileName.isEmpty()) {
            publicKey = readPublicKey(publicKeyFileName);
        }
        
        PublicKeyEntry keyEntry = new PublicKeyEntry();
        keyEntry.setId(keyId);
        keyEntry.setKey(Crypto.ybase64EncodeString(publicKey));
        keyEntry = ZMS.putPublicKeyEntry(domainName, serviceName, keyId, AUDITREF, keyEntry);
        return keyEntry;
    }
    
    private static PublicKeyEntry deletePublicKey(String[] params) {
        String domainName = params[1];
        String serviceName = params[2];
        String keyId = params[3];
        PublicKeyEntry keyEntry = new PublicKeyEntry();
        keyEntry = ZMS.deletePublicKeyEntry(domainName, serviceName, keyId, AUDITREF);
        return keyEntry;
    }
    
    private static String readPublicKey(String file) {
        if (null == file || file.isEmpty()) {
            throw new IllegalArgumentException(file  +  " is missing");
        }
        StringBuilder sb = new StringBuilder();
        try (BufferedReader reader = new BufferedReader(new FileReader(file))) {
            String line;
            while ((line = reader.readLine()) != null) {
                line = line.trim();
                sb.append(line);
                sb.append('\n');
            }
        } catch (IOException e) {
            System.out.println("Error reading from file: " + file);
        }
        return sb.toString();
    }
    
}
