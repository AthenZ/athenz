/**
 * Copyright 2019 Oath Holdings, Inc.
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
package com.yahoo.athenz.example.zts.tls.client;

import javax.net.ssl.SSLContext;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import com.yahoo.athenz.zts.PublicKeyEntry;
import com.yahoo.athenz.zts.AccessTokenResponse;
import com.yahoo.athenz.zts.ZTSClient;
import com.yahoo.athenz.zts.ZTSClientException;
import com.oath.auth.KeyRefresher;
import com.oath.auth.Utils;

public class ZTSTLSClientAccessToken {

    public ZTSTLSClientAccessToken() {
    }
    
    public static void main(String[] args) {
        
        // parse our command line to retrieve required input
        
        CommandLine cmd = parseCommandLine(args);

        final String domainName = cmd.getOptionValue("domain").toLowerCase();
        final String ztsUrl = cmd.getOptionValue("ztsurl");
        final String keyPath = cmd.getOptionValue("key");
        final String certPath = cmd.getOptionValue("cert");
        final String trustStorePath = cmd.getOptionValue("trustStorePath");
        final String trustStorePassword = cmd.getOptionValue("trustStorePassword");
        final String idTokenService = cmd.getOptionValue("idTokenService");

        // we are going to setup our service private key and
        // certificate into a ssl context that we can use with
        // our zts client
        
        try {
            KeyRefresher keyRefresher = Utils.generateKeyRefresher(trustStorePath, trustStorePassword,
                    certPath, keyPath);
            SSLContext sslContext = Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(),
                    keyRefresher.getTrustManagerProxy());
            
            try (ZTSClient ztsClient = new ZTSClient(ztsUrl, sslContext)) {

                try {
                    AccessTokenResponse tokenResponse = ztsClient.getAccessToken(domainName, null, idTokenService, 3600, false);
                    tokenResponse = ztsClient.getAccessToken(domainName, null, "backend", 3600, false);
                    System.out.println("AccessToken: " + tokenResponse.getAccess_token());
                    System.out.println("IDToken: " + tokenResponse.getId_token());
                    System.out.println("Scope: " + tokenResponse.getScope());
                    System.out.println("ExpriresIn: " + tokenResponse.getExpires_in());
                    System.out.println("TokenType: " + tokenResponse.getToken_type());

                } catch (ZTSClientException ex) {
                    System.out.println("Unable to retrieve access token: " + ex.getMessage());
                    System.exit(2);
                }
            }
        } catch (Exception ex) {
            System.out.println("Exception: " + ex.getMessage());
            ex.printStackTrace();
            System.exit(1);
        }
    }
    
    private static CommandLine parseCommandLine(String[] args) {
        
        Options options = new Options();
        
        Option domain = new Option("d", "domain", true, "domain name");
        domain.setRequired(true);
        options.addOption(domain);
        
        Option key = new Option("k", "key", true, "private key path");
        key.setRequired(true);
        options.addOption(key);
        
        Option cert = new Option("c", "cert", true, "certficate path");
        cert.setRequired(true);
        options.addOption(cert);
        
        Option trustStore = new Option("t", "trustStorePath", true, "CA TrustStore path");
        trustStore.setRequired(true);
        options.addOption(trustStore);
        
        Option trustStorePassword = new Option("p", "trustStorePassword", true, "CA TrustStore password");
        trustStorePassword.setRequired(true);
        options.addOption(trustStorePassword);
        
        Option ztsUrl = new Option("z", "ztsurl", true, "ZTS Server url");
        ztsUrl.setRequired(true);
        options.addOption(ztsUrl);
        
        Option idTokenService = new Option("s", "idTokenService", true, "ID Token Service Name");
        idTokenService.setRequired(false);
        options.addOption(idTokenService);
        
        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd = null;
        
        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp("zts-access-token-client", options);
            System.exit(1);
        }
        
        return cmd;
    }
}
