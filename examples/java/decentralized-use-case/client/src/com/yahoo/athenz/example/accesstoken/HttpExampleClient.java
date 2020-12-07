/*
 *  Copyright 2020 Verizon Media
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
package com.yahoo.athenz.example.accesstoken;

import com.oath.auth.KeyRefresher;
import com.oath.auth.Utils;
import com.yahoo.athenz.zts.AccessTokenResponse;
import com.yahoo.athenz.zts.ZTSClient;
import org.apache.commons.cli.*;

import javax.net.ssl.HttpsURLConnection;
import javax.net.ssl.SSLContext;
import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.net.HttpURLConnection;
import java.net.MalformedURLException;
import java.net.URL;
import java.util.ArrayList;
import java.util.List;

public class HttpExampleClient {

    public HttpExampleClient() {
    }
    
    public static void main(String[] args) throws MalformedURLException, IOException {
        
        // parse our command line to retrieve required input
        
        CommandLine cmd = parseCommandLine(args);

        final String domainName = cmd.getOptionValue("domain");
        final String providerRole = cmd.getOptionValue("provider-role");
        String serviceName = cmd.getOptionValue("service");
        final String url = cmd.getOptionValue("url");
        final String ztsUrl = cmd.getOptionValue("ztsurl");
        final String keyPath = cmd.getOptionValue("key");
        final String certPath = cmd.getOptionValue("cert");
        final String trustStorePath = cmd.getOptionValue("trustStorePath");
        final String trustStorePassword = cmd.getOptionValue("trustStorePassword");

        // we are going to setup our service private key and
        // certificate into a ssl context that we can use with
        // our http client

        try {
            KeyRefresher keyRefresher = Utils.generateKeyRefresher(trustStorePath, trustStorePassword,
                    certPath, keyPath);
            keyRefresher.startup();
            SSLContext sslContext = Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(),
                    keyRefresher.getTrustManagerProxy());

            HttpsURLConnection.setDefaultSSLSocketFactory(sslContext.getSocketFactory());

            ZTSClient ztsClient = new ZTSClient(ztsUrl, sslContext);

            List<String> roles = new ArrayList<>();
            roles.add(providerRole); // Can be several of roles. Our example only use one
            AccessTokenResponse accessTokenResponse = ztsClient.getAccessToken(domainName, roles, serviceName, 0, true);
            String accessToken = accessTokenResponse == null ? null : accessTokenResponse.getToken_type() + " " + accessTokenResponse.getAccess_token();

            HttpsURLConnection con = (HttpsURLConnection) new URL(url).openConnection();
            con.setReadTimeout(15000);
            con.setDoOutput(true);
            // Set access token
            con.setRequestProperty (ZTSClient.getHeader(), accessToken);
            con.connect();

            // now process our request
            int responseCode = con.getResponseCode();
            switch (responseCode) {
                case HttpURLConnection.HTTP_FORBIDDEN:
                    System.out.println("Request was forbidden - not authorized: " + con.getResponseMessage());
                    break;
                case HttpURLConnection.HTTP_OK:
                    System.out.println("Successful response: ");
                    try (BufferedReader in = new BufferedReader(new InputStreamReader(con.getInputStream()))) {
                        String inputLine;
                        while ((inputLine = in.readLine()) != null) {
                            System.out.println(inputLine);
                        }
                    }
                    break;
                default:
                    System.out.println("Request failed - response status code: " + responseCode);
            }

            try (BufferedReader br = new BufferedReader(new InputStreamReader(con.getInputStream()))) {
                StringBuilder sb = new StringBuilder();
                String line;
                while ((line = br.readLine()) != null) {
                    sb.append(line);
                }
                System.out.println("Data output: " + sb.toString());
            }

        } catch (Exception ex) {
            System.out.println("Exception: " + ex.getMessage());
            ex.printStackTrace();
            System.exit(1);
        }
    }

    private static CommandLine parseCommandLine(String[] args) {

        Options options = new Options();

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

        Option url = new Option("u", "url", true, "request url");
        url.setRequired(true);
        options.addOption(url);

        Option ztsUrl = new Option("z", "ztsurl", true, "ZTS Server url");
        ztsUrl.setRequired(true);
        options.addOption(ztsUrl);

        Option domain = new Option("d", "domain", true, "domain name");
        domain.setRequired(true);
        options.addOption(domain);

        Option providerRole = new Option("pr", "provider-role", true, "Provider role name");
        providerRole.setRequired(true);
        options.addOption(providerRole);

        Option service = new Option("s", "service", true, "service name");
        service.setRequired(true);
        options.addOption(service);

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp("zts-tls-client", options);
            System.exit(1);
        }

        return cmd;
    }
}
