/**
 * Copyright 2017 Yahoo Inc.
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
package com.yahoo.athenz.example.instance;

import java.io.File;
import java.io.IOException;
import java.net.MalformedURLException;
import java.security.PrivateKey;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.operator.OperatorCreationException;

import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.zts.InstanceIdentity;
import com.yahoo.athenz.zts.InstanceRefreshInformation;
import com.yahoo.athenz.zts.ZTSClient;
import com.yahoo.athenz.zts.ZTSClientException;

public class InstanceClientRefresh {

    public InstanceClientRefresh() {
    }
    
    public static String generateCSR(String domainName, String serviceName,
            String instanceId, String dnsSuffix, PrivateKey key) {
        
        final String dn = "cn=" + domainName + "." + serviceName + ",o=Athenz";
        
        // now let's generate our dsnName field based on our principal's details
        
        StringBuilder dnsName = new StringBuilder(128);
        dnsName.append(serviceName);
        dnsName.append('.');
        dnsName.append(domainName.replace('.', '-'));
        dnsName.append('.');
        dnsName.append(dnsSuffix);
        
        GeneralName[] sanArray = new GeneralName[2];
        sanArray[0] = new GeneralName(GeneralName.dNSName, new DERIA5String(dnsName.toString()));
        
        // next we include our instance id
        
        StringBuilder dnsInstance = new StringBuilder(128);
        dnsInstance.append(instanceId);
        dnsInstance.append(".instanceid.athenz.");
        dnsInstance.append(dnsSuffix);
        
        sanArray[1] = new GeneralName(GeneralName.dNSName, new DERIA5String(dnsInstance.toString()));
        
        String csr = null;
        try {
            csr = Crypto.generateX509CSR(key, dn, sanArray);
        } catch (OperatorCreationException | IOException ex) {
            System.err.println(ex.getMessage());
        }
        
        return csr;
    }
    
    public static void main(String[] args) throws MalformedURLException, IOException {
        
        // parse our command line to retrieve required input
        
        CommandLine cmd = parseCommandLine(args);

        String domainName = cmd.getOptionValue("domain").toLowerCase();
        String serviceName = cmd.getOptionValue("service").toLowerCase();
        String provider = cmd.getOptionValue("provider").toLowerCase();
        String instance = cmd.getOptionValue("instance");
        String dnsSuffix = cmd.getOptionValue("dnssuffix");
        String instanceKeyPath = cmd.getOptionValue("instancekey");
        String ztsUrl = cmd.getOptionValue("ztsurl");
        
        // now we need to generate our CSR so we can get
        // a TLS certificate for our instance
        
        PrivateKey instanceKey = Crypto.loadPrivateKey(new File(instanceKeyPath));
        String csr = generateCSR(domainName, serviceName, instance, dnsSuffix, instanceKey);
        
        if (csr == null) {
            System.err.println("Unable to generate CSR for instance");
            System.exit(1);
        }
        System.out.println("CSR: \n" + csr + "\n");

        // now let's generate our instance refresh object that will be sent
        // to the ZTS Server
        
        InstanceRefreshInformation info = new InstanceRefreshInformation()
                .setToken(true)
                .setCsr(csr);

        // now contact zts server to request identity for instance
        
        InstanceIdentity identity = null;
        try (ZTSClient ztsClient = new ZTSClient(ztsUrl)) {
            identity = ztsClient.postInstanceRefreshInformation(provider, domainName,
                    serviceName, instance, info);
        } catch (ZTSClientException ex) {
            System.out.println("Unable to register instance: " + ex.getMessage());
            System.exit(2);
        }

        System.out.println("Identity TLS Certificate: \n" + identity.getX509Certificate());
    }
    
    private static CommandLine parseCommandLine(String[] args) {
        
        Options options = new Options();
        
        Option domain = new Option("d", "domain", true, "domain name");
        domain.setRequired(true);
        options.addOption(domain);
        
        Option service = new Option("s", "service", true, "service name");
        service.setRequired(true);
        options.addOption(service);
        
        Option provider = new Option("p", "provider", true, "provider name");
        provider.setRequired(true);
        options.addOption(provider);
        
        Option instance = new Option("i", "instance", true, "instance id");
        instance.setRequired(true);
        options.addOption(instance);
        
        Option dnsSuffix = new Option("dns", "dnssuffix", true, "provider dns suffix");
        dnsSuffix.setRequired(true);
        options.addOption(dnsSuffix);
        
        Option instanceKey = new Option("ik", "instancekey", true, "instance private key path");
        instanceKey.setRequired(true);
        options.addOption(instanceKey);
        
        Option ztsUrl = new Option("z", "ztsurl", true, "ZTS Server url");
        ztsUrl.setRequired(true);
        options.addOption(ztsUrl);
        
        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd = null;
        
        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp("instance-client", options);
            System.exit(1);
        }
        
        return cmd;
    }
}
