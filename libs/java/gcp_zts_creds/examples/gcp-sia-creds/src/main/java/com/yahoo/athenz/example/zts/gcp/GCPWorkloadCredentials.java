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

import com.yahoo.athenz.creds.gcp.GCPSIACredentials;
import org.apache.commons.cli.*;

public class GCPWorkloadCredentials {
    
    public static void main(String[] args) throws Exception {
        
        // parse our command line to retrieve required input
        
        CommandLine cmd = parseCommandLine(args);

        final String domainName = cmd.getOptionValue("domain");
        final String serviceName = cmd.getOptionValue("service");
        final String region = cmd.getOptionValue("region");
        final String ztsUrl = cmd.getOptionValue("ztsurl");
        final String sanDNSDomain = cmd.getOptionValue("dnsdomain");

        // generate our provider id
        final String athenzProvider = "sys.gcp." + region;

        // fetch and return our athenz identity that includes the private key
        // and x.509 certificate in both object and PEM formats. The returned
        // object also returns the list of CA certificates in PEM format.
        GCPSIACredentials.X509KeyPair x509KeyPair = GCPSIACredentials.getGCPWorkloadServiceCertificate(
                domainName, serviceName, athenzProvider, ztsUrl, sanDNSDomain,
                null, null, null, null, null, null);

        System.out.println("Service Identity X.509 Certificate: \n" + x509KeyPair.certificatePem);
    }

    private static CommandLine parseCommandLine(String[] args) {
        
        Options options = new Options();
        
        Option domain = new Option("d", "domain", true, "domain name");
        domain.setRequired(true);
        options.addOption(domain);
        
        Option service = new Option("s", "service", true, "service name");
        service.setRequired(true);
        options.addOption(service);
        
        Option region = new Option("r", "region", true, "gcp region");
        region.setRequired(true);
        options.addOption(region);

        Option ztsUrl = new Option("z", "ztsurl", true, "ZTS Server url");
        ztsUrl.setRequired(true);
        options.addOption(ztsUrl);

        Option dnsDomain = new Option("n", "dnsdomain", true, "san dns domain");
        dnsDomain.setRequired(true);
        options.addOption(dnsDomain);

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();

        try {
            return parser.parse(options, args);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp("gcp-workload-credentials", options);
            System.exit(1);
        }

        return null;
    }
}
