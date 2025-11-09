/**
 * Copyright The Athenz Authors
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

import com.yahoo.athenz.zts.*;
import com.oath.auth.KeyRefresher;
import com.oath.auth.Utils;
import org.apache.commons.cli.*;

import java.util.Collections;

public class ZTSTLSClientJAGTokenExchange {

    public static void main(String[] args) {

        // parse our command line to retrieve required input

        CommandLine cmd = parseCommandLine(args);

        final String domainName = cmd.getOptionValue("domain").toLowerCase();
        final String ztsUrl = cmd.getOptionValue("ztsurl");
        final String idKeyPath = cmd.getOptionValue("idKey");
        final String idCertPath = cmd.getOptionValue("idCert");
        final String trustStorePath = cmd.getOptionValue("trustStorePath");
        final String trustStorePassword = cmd.getOptionValue("trustStorePassword");
        final String clientId = cmd.getOptionValue("clientId");
        final String expiryTime = cmd.getOptionValue("expiryTime");
        final String roleName = cmd.getOptionValue("roleName");
        final String resource = cmd.getOptionValue("resource");
        final String svcKeyPath = cmd.getOptionValue("svcKey");
        final String svcCertPath = cmd.getOptionValue("svcCert");

        // we are going to set up our service private key and
        // certificate into a ssl context that we can use with
        // our zts client
        
        try {
            KeyRefresher keyRefresher = Utils.generateKeyRefresher(trustStorePath, trustStorePassword,
                    idCertPath, idKeyPath);
            SSLContext sslContext = Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(),
                    keyRefresher.getTrustManagerProxy());

            String idToken = null;
            try (ZTSClient ztsClient = new ZTSClient(ztsUrl, sslContext)) {

                // first we need to request an id token for the user

                IDTokenRequestBuilder builder = IDTokenRequestBuilder.newBuilder(IDTokenRequestBuilder.OPENID_RESPONSE_TYPE_ID_TOKEN)
                        .clientId(clientId)
                        .scope("openid")
                        .keyType("EC")
                        .expiryTime(Integer.parseInt(expiryTime));

                OIDCResponse response = ztsClient.getIDToken(builder, false);

                idToken = response.getId_token();
                System.out.println("Our ID Token is:");
                System.out.println(idToken);

            } catch (ZTSClientException ex) {
                System.out.println("Unable to retrieve id token: " + ex.getMessage());
                System.exit(2);
            }

            KeyRefresher keyRefresherJag = Utils.generateKeyRefresher(trustStorePath, trustStorePassword,
                    svcCertPath, svcKeyPath);
            SSLContext sslContextJag = Utils.buildSSLContext(keyRefresherJag.getKeyManagerProxy(),
                    keyRefresherJag.getTrustManagerProxy());

            // now we need to get our jag token

            try (ZTSClient ztsClient = new ZTSClient(ztsUrl, sslContextJag)) {

                // generate our jag token request

                OAuthTokenRequestBuilder builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_TOKEN_EXCHANGE)
                        .domainName(domainName)
                        .requestedTokenType(OAuthTokenRequestBuilder.OAUTH_TOKEN_TYPE_JAG)
                        .audience(ztsUrl)
                        .resource(resource)
                        .roleNames(Collections.singletonList(roleName))
                        .subjectTokenType(OAuthTokenRequestBuilder.OAUTH_TOKEN_TYPE_ID)
                        .subjectToken(idToken);

                AccessTokenResponse tokenResponse = ztsClient.getJAGToken(builder);

                String jagToken = tokenResponse.getAccess_token();
                System.out.println("JAG Token is:");
                System.out.println(jagToken);


                builder = OAuthTokenRequestBuilder.newBuilder(OAuthTokenRequestBuilder.OAUTH_GRANT_JWT_BEARER)
                        .assertion(jagToken);

                tokenResponse = ztsClient.getJAGExchangeToken(builder);
                System.out.println("JAG Exchange Token is:");
                System.out.println(tokenResponse.getAccess_token());

            } catch (ZTSClientException ex) {
                System.out.println("Unable to retrieve jag exchange token: " + ex.getMessage());
                System.exit(2);
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

        Option idKey = new Option("k", "idKey", true, "private key path for id token");
        idKey.setRequired(true);
        options.addOption(idKey);

        Option idCert = new Option("c", "idCert", true, "certificate path for id token");
        idCert.setRequired(true);
        options.addOption(idCert);

        Option trustStore = new Option("t", "trustStorePath", true, "CA TrustStore path");
        trustStore.setRequired(true);
        options.addOption(trustStore);

        Option trustStorePassword = new Option("p", "trustStorePassword", true, "CA TrustStore password");
        trustStorePassword.setRequired(true);
        options.addOption(trustStorePassword);

        Option ztsUrl = new Option("z", "ztsurl", true, "ZTS Server url");
        ztsUrl.setRequired(true);
        options.addOption(ztsUrl);

        Option clientId = new Option("s", "clientId", true, "ID Token client ID");
        clientId.setRequired(true);
        options.addOption(clientId);

        Option roleName = new Option("r", "roleName", true, "Role name for access token");
        roleName.setRequired(true);
        options.addOption(roleName);

        Option resource = new Option("h", "resource", true, "resource object");
        resource.setRequired(true);
        options.addOption(resource);

        Option expiryTime = new Option("e", "expiryTime", true, "Expiry Time in seconds");
        expiryTime.setRequired(true);
        options.addOption(expiryTime);

        Option svcKey = new Option("v", "svcKey", true, "private key path for service token");
        svcKey.setRequired(true);
        options.addOption(svcKey);

        Option svcCert = new Option("w", "svcCert", true, "certificate path for service token");
        svcCert.setRequired(true);
        options.addOption(svcCert);

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
