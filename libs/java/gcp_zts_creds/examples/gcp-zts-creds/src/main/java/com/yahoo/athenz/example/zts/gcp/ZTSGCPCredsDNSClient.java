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
package com.yahoo.athenz.example.zts.gcp;

import com.google.auth.oauth2.*;
import com.google.cloud.dns.Dns;
import com.google.cloud.dns.DnsOptions;
import com.google.cloud.dns.RecordSet;
import com.oath.auth.KeyRefresherException;
import com.yahoo.athenz.creds.gcp.GCPZTSCredentials;
import org.apache.commons.cli.*;
import java.io.IOException;
import java.util.Collections;

public class ZTSGCPCredsDNSClient {
    
    public static void main(String[] args) throws KeyRefresherException, IOException, InterruptedException {
        
        // parse our command line to retrieve required input
        
        CommandLine cmd = parseCommandLine(args);

        final String domainName = cmd.getOptionValue("domain").toLowerCase();
        final String roleName = cmd.getOptionValue("role").toLowerCase();
        final String ztsUrl = cmd.getOptionValue("ztsurl");
        final String keyPath = cmd.getOptionValue("key");
        final String certPath = cmd.getOptionValue("cert");
        final String clientId = cmd.getOptionValue("clientid");
        final String projectId = cmd.getOptionValue("projectId");
        final String projectNumber = cmd.getOptionValue("projectNumber");
        final String trustStorePath = cmd.getOptionValue("trustStorePath");
        final String trustStorePassword = cmd.getOptionValue("trustStorePassword");
        final String workLoadPoolName = cmd.getOptionValue("workLoadPoolName");
        final String workLoadProviderName = cmd.getOptionValue("workLoadProviderName");
        final String redirectUriSuffix = cmd.getOptionValue("redirectUriSuffix");
        final String serviceAccount = cmd.getOptionValue("serviceAccount");

        // create our credentials object based on the input data

        GCPZTSCredentials gcpztsCredentials = new GCPZTSCredentials.Builder()
                .setZtsUrl(ztsUrl)
                .setProjectId(projectId)
                .setProjectNumber(projectNumber)
                .setWorkloadPoolName(workLoadPoolName)
                .setWorkloadProviderName(workLoadProviderName)
                .setServiceAccountName(serviceAccount)
                .setCertFile(certPath)
                .setKeyFile(keyPath)
                .setTrustStorePath(trustStorePath)
                .setTrustStorePassword(trustStorePassword.toCharArray())
                .setCertRefreshTimeout(30000)
                .setDomainName(domainName)
                .setRoleNames(Collections.singletonList(roleName))
                .setClientId(clientId)
                .setRedirectUriSuffix(redirectUriSuffix)
                .setTokenLifetimeSeconds(3600)
                .build();

        // create our Google external account credentials

        ExternalAccountCredentials credentials = gcpztsCredentials.getTokenAPICredentials();

        try {

            // list all the zones and then iterate through all the record sets
            // and display all DNS TXT records

            Dns dns = DnsOptions.newBuilder().setCredentials(credentials).setProjectId(projectId)
                    .build().getService();

            dns.listZones().iterateAll().forEach(zone -> {
                zone.listRecordSets().iterateAll().forEach(recordSet -> {
                    System.out.println("record: " + recordSet.getName() + " type: " + recordSet.getType());
                    if (recordSet.getType().equals(RecordSet.Type.TXT)) {
                        System.out.println(recordSet.getRecords());
                    }
                });
            });
        } catch (Exception ex) {
            ex.printStackTrace();
        }

        gcpztsCredentials.close();
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
        
        Option cert = new Option("c", "cert", true, "certificate path");
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

        Option clientId = new Option("i", "clientid", true, "client id");
        clientId.setRequired(true);
        options.addOption(clientId);

        Option zone = new Option("b", "zone", true, "zone name");
        zone.setRequired(true);
        options.addOption(zone);

        Option projectId = new Option("j", "projectId", true, "project id");
        projectId.setRequired(true);
        options.addOption(projectId);

        Option projectNumber = new Option("n", "projectNumber", true, "project id");
        projectNumber.setRequired(true);
        options.addOption(projectNumber);

        Option workLoadPoolName = new Option("w", "workLoadPoolName", true, "workload identity pool name");
        workLoadPoolName.setRequired(true);
        options.addOption(workLoadPoolName);

        Option workLoadProviderName = new Option("m", "workLoadProviderName", true, "workload identity provider name");
        workLoadProviderName.setRequired(true);
        options.addOption(workLoadProviderName);

        Option redirectUriSuffix = new Option("f", "redirectUriSuffix", true, "redirect uri prefix");
        redirectUriSuffix.setRequired(true);
        options.addOption(redirectUriSuffix);

        Option serviceAccount = new Option("s", "serviceAccount", true, "service account name");
        serviceAccount.setRequired(true);
        options.addOption(serviceAccount);

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd = null;
        
        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp("zts-gcp-creds-client", options);
            System.exit(1);
        }
        
        return cmd;
    }
}
