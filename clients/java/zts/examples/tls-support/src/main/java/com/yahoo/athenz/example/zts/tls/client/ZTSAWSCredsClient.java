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

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.yahoo.athenz.zts.PublicKeyEntry;
import com.yahoo.athenz.zts.ZTSClient;
import com.yahoo.athenz.zts.AWSCredentialsProviderImpl;
import com.yahoo.athenz.zts.ZTSClientException;
import com.amazonaws.auth.AWSCredentials;
import com.amazonaws.auth.AWSCredentialsProvider;
import com.oath.auth.KeyRefresher;
import com.oath.auth.Utils;

public class ZTSAWSCredsClient {

    private static final Logger LOG = LoggerFactory.getLogger(ZTSAWSCredsClient.class);

    public ZTSAWSCredsClient() {
    }
    
    public static void main(String[] args) {
        
        // parse our command line to retrieve required input
        
        CommandLine cmd = parseCommandLine(args);

        final String domainName = cmd.getOptionValue("domain").toLowerCase();
        final String roleName = cmd.getOptionValue("role").toLowerCase();
        final String ztsUrl = cmd.getOptionValue("ztsurl");
        final String keyPath = cmd.getOptionValue("key");
        final String certPath = cmd.getOptionValue("cert");
        final String externalId = cmd.getOptionValue("id");
        final String minTime = cmd.getOptionValue("min");
        final String maxTime = cmd.getOptionValue("max");
        final String trustStorePath = cmd.getOptionValue("trustStorePath");
        final String trustStorePassword = cmd.getOptionValue("trustStorePassword");

        // we are going to setup our service private key and
        // certificate into a ssl context that we can use with
        // our zts client
        
        try {
            KeyRefresher keyRefresher = Utils.generateKeyRefresher(trustStorePath, trustStorePassword,
                    certPath, keyPath);
            keyRefresher.startup();
            SSLContext sslContext = Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(),
                    keyRefresher.getTrustManagerProxy());
            
            // obtain temporary credential provider for our domain and role

            Integer minTimeSeconds = (minTime != null) ? Integer.parseInt(minTime) : null;
            Integer maxTimeSeconds = (maxTime != null) ? Integer.parseInt(maxTime) : null;
            AWSCredentialsProviderImpl awsCredProvider = new AWSCredentialsProviderImpl(ztsUrl,
                    sslContext, domainName, roleName, externalId, minTimeSeconds, maxTimeSeconds);

            // retrieve and display aws temporary creds. Typically you just pass
            // the AWSCredentialsProvider object to any AWS api that requires it.
            // for example, when creating an AWS S3 client
            //      AmazonS3 s3client = AmazonS3ClientBuilder.standard()
            //          .withCredentials(awsCredProvider).withClientConfiguration(cltConf)
            //          .withRegion(getRegion()).build();
          
            retrieveAWSTempCreds(awsCredProvider);
            
            // once we're done with our api and we no longer need our
            // provider we need to make sure to close it
            
            awsCredProvider.close();
            
        } catch (Exception ex) {
            System.out.println("Exception: " + ex.getMessage());
            ex.printStackTrace();
            System.exit(1);
        }
    }
    
    private static boolean retrieveAWSTempCreds(AWSCredentialsProvider awsCredProvider) {
        
        try {
            // just for testing purposes we're going to run this code
            // for 2 hours and keep asking for credentials every minute
            // to make sure zts client is caching the creds and giving
            // us new ones when they're about to expire
            
            for (int i = 0; i < 120; i++) {
                AWSCredentials awsCreds = awsCredProvider.getCredentials();
                if (awsCreds == null) {
                    System.out.println("Error: AWS Credentials are not available");
                    return false;
                }
                System.out.println("AWS Temporary Credentials:\n");
                System.out.println("\tAccess Key Id : " + awsCreds.getAWSAccessKeyId());
                System.out.println("\tSecret Key    : " + awsCreds.getAWSSecretKey());
                try {
                    Thread.sleep(60000);
                } catch (InterruptedException ex) {
                }
            }
        } catch (ZTSClientException ex) {
            System.out.println("Unable to retrieve AWS credentials: " + ex.getMessage());
            return false;
        }
        return true;
    }
    
    private static CommandLine parseCommandLine(String[] args) {
        
        Options options = new Options();
        
        Option domain = new Option("d", "domain", true, "domain name");
        domain.setRequired(true);
        options.addOption(domain);
        
        Option role = new Option("r", "role", true, "role name");
        role.setRequired(true);
        options.addOption(role);
        
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

        Option externalId = new Option("i", "id", true, "external id");
        externalId.setRequired(false);
        options.addOption(externalId);

        Option minTime = new Option("n", "min", true, "min expiry time in seconds");
        minTime.setRequired(false);
        options.addOption(minTime);

        Option maxTime = new Option("x", "max", true, "max expiry time in seconds");
        maxTime.setRequired(false);
        options.addOption(maxTime);

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd = null;
        
        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp("zts-aws-creds-client", options);
            System.exit(1);
        }
        
        return cmd;
    }
}
