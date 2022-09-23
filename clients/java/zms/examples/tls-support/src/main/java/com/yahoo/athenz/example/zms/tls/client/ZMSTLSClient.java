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
package com.yahoo.athenz.example.zms.tls.client;

import javax.net.ssl.SSLContext;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import com.yahoo.athenz.zms.*;
import com.yahoo.athenz.zms.ZMSClient;
import com.yahoo.athenz.zms.ZMSClientException;
import com.oath.auth.KeyRefresher;
import com.oath.auth.Utils;

public class ZMSTLSClient {

    public ZMSTLSClient() {
    }
    
    public static void main(String[] args) {
        
        // parse our command line to retrieve required input
        
        CommandLine cmd = parseCommandLine(args);

        final String command = cmd.getOptionValue("method").toLowerCase();
        final String resource = cmd.getOptionValue("resource");
        final String action = cmd.getOptionValue("action");
        final String domain = cmd.getOptionValue("domain");
        final String principal = cmd.getOptionValue("principal");
        final String zmsUrl = cmd.getOptionValue("zmsurl");
        final String keyPath = cmd.getOptionValue("key");
        final String certPath = cmd.getOptionValue("cert");
        final String trustStorePath = cmd.getOptionValue("trustStorePath");
        final String trustStorePassword = cmd.getOptionValue("trustStorePassword");
        final String roleName = cmd.getOptionValue("role");

        // we are going to setup our service private key and
        // certificate into a ssl context that we can use with
        // our zms client
        
        try {
            KeyRefresher keyRefresher = Utils.generateKeyRefresher(trustStorePath, trustStorePassword,
                    certPath, keyPath);
            keyRefresher.startup();
            SSLContext sslContext = Utils.buildSSLContext(keyRefresher.getKeyManagerProxy(),
                    keyRefresher.getTrustManagerProxy());
            
            try (ZMSClient zmsClient = new ZMSClient(zmsUrl, sslContext)) {

                try {
                    switch (command) {
                        case "getdomainrolemembers":
                            DomainRoleMembers drMembers = zmsClient.getDomainRoleMembers(domain);
                            for (DomainRoleMember member : drMembers.getMembers()) {
                                System.out.println("Member: " + member.getMemberName());
                                for (MemberRole role : member.getMemberRoles()) {
                                    System.out.println("  Role: " + role.getRoleName());
                                }
                            }
                            break;
                        case "getpendingdomainrolememberslist":
                            DomainRoleMembership pendMembers = zmsClient.getPendingDomainRoleMembersList(principal);
                            for (DomainRoleMembers members : pendMembers.getDomainRoleMembersList()) {
                                for (DomainRoleMember member : members.getMembers()) {
                                    System.out.println("Member: " + member.getMemberName());
                                    for (MemberRole role : member.getMemberRoles()) {
                                        System.out.println("  Role: " + role.getRoleName());
                                    }
                                }
                            }
                            break;
                        case "access":
                            Access access = zmsClient.getAccess(action, resource, null, principal);
                            System.out.println("Access: " + access.getGranted());
                            break;
                        case "getrole":
                            Role sampleRole = zmsClient.getRole(domain, roleName);
                            System.out.println("Role: " + sampleRole.getName());
                            break;
                    }
                } catch (ZMSClientException ex) {
                    System.out.println("Unable to carry out request: " + ex.getMessage());
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

        Option command = new Option("m", "method", true, "zms api method name");
        command.setRequired(true);
        options.addOption(command);

        Option domain = new Option("d", "domain", true, "domain name");
        domain.setRequired(false);
        options.addOption(domain);

        Option resource = new Option("r", "resource", true, "resource value");
        resource.setRequired(false);
        options.addOption(resource);
        
        Option action = new Option("a", "action", true, "action");
        action.setRequired(false);
        options.addOption(action);
        
        Option principal = new Option("u", "principal", true, "principal to check for");
        principal.setRequired(false);
        options.addOption(principal);
        
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
        
        Option zmsUrl = new Option("z", "zmsurl", true, "ZMS Server url");
        zmsUrl.setRequired(true);
        options.addOption(zmsUrl);

        Option role = new Option("ro", "role", true, "name of the role");
        role.setRequired(false);
        options.addOption(role);
        
        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd = null;
        
        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp("zms-tls-client", options);
            System.exit(1);
        }
        
        return cmd;
    }
}
