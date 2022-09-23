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
import io.jsonwebtoken.*;
import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.apache.http.conn.DnsResolver;

import com.oath.auth.KeyRefresher;
import com.oath.auth.Utils;

import java.math.BigInteger;
import java.security.*;
import java.security.spec.*;
import java.util.Base64;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.concurrent.ConcurrentHashMap;
import java.net.InetAddress;
import java.net.UnknownHostException;

public class ZTSTLSClientAccessToken {

    public static final String CLAIM_SCOPE = "scp";
    public static final String CLAIM_UID = "uid";
    public static final String CLAIM_CLIENT_ID = "client_id";

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
        final String expiryTime = cmd.getOptionValue("expiryTime");
        final String hostnameOverride = cmd.getOptionValue("hostnameOverride");
        final String resolveHostname = cmd.getOptionValue("resolveHostname");

        // we are going to setup our service private key and
        // certificate into a ssl context that we can use with
        // our zts client
        
        try {
            KeyRefresher keyRefresher = Utils.generateKeyRefresher(trustStorePath, trustStorePassword,
                    certPath, keyPath);
            SSLContext sslContext = Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(),
                    keyRefresher.getTrustManagerProxy());

            if (resolveHostname != null && !resolveHostname.isEmpty()) {
                ZTSClient.setDnsResolver(getDnsResolver(resolveHostname));
            }

            if (hostnameOverride != null && !hostnameOverride.isEmpty()) {
                ZTSClient.setX509CertDnsName(hostnameOverride);
            }

            try (ZTSClient ztsClient = new ZTSClient(ztsUrl, sslContext)) {

                long expiryTimeSeconds = (expiryTime != null) ? Long.parseLong(expiryTime) : 0;

                try {
                    AccessTokenResponse tokenResponse = ztsClient.getAccessToken(domainName, null,
                            idTokenService, expiryTimeSeconds, false);

                    System.out.println("AccessToken: " + tokenResponse.getAccess_token());
                    System.out.println("IDToken: " + tokenResponse.getId_token());
                    System.out.println("Scope: " + tokenResponse.getScope());
                    System.out.println("ExpiresIn: " + tokenResponse.getExpires_in());
                    System.out.println("TokenType: " + tokenResponse.getToken_type());

                    // now we're going to validate our access token - first we need to fetch
                    // the keys from the zts server

                    JWKList jwkList = ztsClient.getJWKList(true);
                    JwtsSigningKeyResolver keyResolver = new JwtsSigningKeyResolver(jwkList);

                    Jws<Claims> claims = Jwts.parser()
                            .setSigningKeyResolver(keyResolver)
                            .setAllowedClockSkewSeconds(60)
                            .parseClaimsJws(tokenResponse.getAccess_token());

                    System.out.println("\nAccess Token was successfully validated\n");

                    final Claims body = claims.getBody();
                    System.out.println("Client id: " + body.get(CLAIM_CLIENT_ID, String.class));
                    System.out.println("Client uid: " + body.get(CLAIM_UID, String.class));
                    System.out.println("Scope: " + String.join(",", body.get(CLAIM_SCOPE, List.class)));

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

        Option hostnameOverride = new Option("h", "hostnameOverride", true, "Hostname verifier support");
        hostnameOverride.setRequired(false);
        options.addOption(hostnameOverride);

        Option resolveHostname = new Option("r", "resolveHostname", true, "Resolve hostname to IP support");
        resolveHostname.setRequired(false);
        options.addOption(resolveHostname);

        Option expiryTime = new Option("e", "expiryTime", true, "Expiry Time in seconds");
        expiryTime.setRequired(false);
        options.addOption(expiryTime);

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

    private static DnsResolver getDnsResolver(final String resolveHostname) throws UnknownHostException {

        int idx = resolveHostname.indexOf(':');
        if (idx == -1) {
            return null;
        }
        final String hostname = resolveHostname.substring(0, idx);
        final String ipAddress = resolveHostname.substring(idx + 1);

        final InetAddress[] inetResponse = new InetAddress[1];
        inetResponse[0] = InetAddress.getByName(resolveHostname.substring(idx + 1));

        DnsResolver dnsResolver = host -> {
            if (host.equalsIgnoreCase(hostname)) {
                return inetResponse;
            }
            throw new UnknownHostException("unknown host: " + host);
        };
        return dnsResolver;
    }
}
