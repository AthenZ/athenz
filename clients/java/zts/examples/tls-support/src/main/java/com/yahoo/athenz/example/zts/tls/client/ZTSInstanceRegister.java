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

import com.oath.auth.KeyRefresher;
import com.oath.auth.Utils;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.zts.*;
import org.apache.commons.cli.*;
import org.bouncycastle.asn1.DERIA5String;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.operator.OperatorCreationException;

import javax.net.ssl.SSLContext;
import java.io.File;
import java.io.IOException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.util.HashMap;
import java.util.List;
import java.util.Map;

public class ZTSInstanceRegister {

    public ZTSInstanceRegister() {
    }
    
    public static void main(String[] args) {
        
        // parse our command line to retrieve required input
        
        CommandLine cmd = parseCommandLine(args);

        final String domainName = cmd.getOptionValue("domain").toLowerCase();
        final String serviceName = cmd.getOptionValue("service").toLowerCase();
        final String ztsUrl = cmd.getOptionValue("ztsurl");
        final String keyPath = cmd.getOptionValue("key");
        final String serviceToken = cmd.getOptionValue("token");
        final String csrDn = cmd.getOptionValue("csrdn");
        final String csrDomain = cmd.getOptionValue("csrdomain");
        
        try {
            try (ZTSClient ztsClient = new ZTSClient(ztsUrl)) {

                try {
                    PrivateKey privateKey = Crypto.loadPrivateKey(new File(keyPath));

                    InstanceRegisterInformation registerInfo = generateInstanceRegisterInfo(domainName,
                            serviceName, privateKey, serviceToken, csrDn, csrDomain);

                    Map<String, List<String>> headers = new HashMap<>();
                    InstanceIdentity identity = ztsClient.postInstanceRegisterInformation(registerInfo, headers);
                    System.out.println("Identity X.509 Certificate: " + identity.getX509Certificate());

                } catch (ZTSClientException ex) {
                    System.out.println("Unable to register instance: " + ex.getMessage());
                    System.exit(2);
                }
            }
        } catch (Exception ex) {
            System.out.println("Exception: " + ex.getMessage());
            ex.printStackTrace();
            System.exit(1);
        }
    }

    private static InstanceRegisterInformation generateInstanceRegisterInfo(final String domainName,
            final String serviceName, PrivateKey privateKey, final String serviceToken,
            final String csrDn, final String csrDomain) {

        if (domainName == null || serviceName == null) {
            throw new IllegalArgumentException("Principal's Domain and Service must be specified");
        }

        if (csrDomain == null) {
            throw new IllegalArgumentException("X509 CSR Domain must be specified");
        }

        // Athenz uses lower case for all elements, so let's
        // generate our dn which will be based on our service name

        final String domain = domainName.toLowerCase();
        final String service = serviceName.toLowerCase();
        final String cn = domain + "." + service;

        String dn = "cn=" + cn;
        if (csrDn != null) {
            dn = dn.concat(",").concat(csrDn);
        }

        // now let's generate our dsnName field based on our principal's details

        final String hostName = service + '.' + domain.replace('.', '-') + '.' + csrDomain;
        final String instanceUri = "athenz://instanceid/" + domain + "/" + service;
        GeneralName[] sanArray = new GeneralName[2];
        sanArray[0] = new GeneralName(GeneralName.dNSName, new DERIA5String(hostName));
        sanArray[1] = new GeneralName(GeneralName.uniformResourceIdentifier, new DERIA5String(instanceUri));

        String csr;
        try {
            csr = Crypto.generateX509CSR(privateKey, dn, sanArray);
        } catch (OperatorCreationException | IOException | NoSuchAlgorithmException ex) {
            throw new ZTSClientException(ZTSClientException.BAD_REQUEST, ex.getMessage());
        }

        return new InstanceRegisterInformation().setCsr(csr).setProvider("sys.auth.zts")
                .setDomain(domain).setService(service).setAttestationData(serviceToken);
    }

    private static CommandLine parseCommandLine(String[] args) {
        
        Options options = new Options();

        Option domain = new Option("d", "domain", true, "domain name");
        domain.setRequired(true);
        options.addOption(domain);

        Option service = new Option("s", "service", true, "service name");
        service.setRequired(true);
        options.addOption(service);

        Option csrdn = new Option("n", "csrdn", true, "csr dn value");
        csrdn.setRequired(true);
        options.addOption(csrdn);

        Option csrdomain = new Option("m", "csrdomain", true, "csr domain value");
        csrdomain.setRequired(true);
        options.addOption(csrdomain);

        Option key = new Option("k", "key", true, "private key path");
        key.setRequired(true);
        options.addOption(key);

        Option token = new Option("t", "token", true, "attestation data token");
        token.setRequired(true);
        options.addOption(token);

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
            formatter.printHelp("zts-instance-register", options);
            System.exit(1);
        }
        
        return cmd;
    }
}
