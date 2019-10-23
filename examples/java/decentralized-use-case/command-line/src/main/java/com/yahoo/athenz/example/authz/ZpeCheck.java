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
package com.yahoo.athenz.example.authz;

import org.apache.commons.cli.CommandLine;
import org.apache.commons.cli.CommandLineParser;
import org.apache.commons.cli.DefaultParser;
import org.apache.commons.cli.HelpFormatter;
import org.apache.commons.cli.Option;
import org.apache.commons.cli.Options;
import org.apache.commons.cli.ParseException;

import com.yahoo.athenz.zpe.AuthZpeClient;
import com.yahoo.athenz.zpe.AuthZpeClient.AccessCheckStatus;

public class ZpeCheck {

    public static void main(String[] args) {

        // parse our command line to retrieve required input

        CommandLine cmd = parseCommandLine(args);

        final String athenzToken = cmd.getOptionValue("token");
        final String athenzResource = cmd.getOptionValue("resource");
        final String athenzAction = cmd.getOptionValue("action");
        final String athenzConf = cmd.getOptionValue("conf");
        final String policyDir = cmd.getOptionValue("policy-dir");

        // initialize Athenz ZPE client which will load
        // all policy files into memory

        System.setProperty("athenz.zpe.policy_dir", policyDir);
        System.setProperty("athenz.athenz_conf", athenzConf);
        AuthZpeClient.init();

        AccessCheckStatus status = AuthZpeClient.allowAccess(athenzToken,
                athenzResource, athenzAction);
        System.out.println("Authorization Check: " + status.toString());
    }

    private static CommandLine parseCommandLine(String[] args) {

        Options options = new Options();

        Option token = new Option("t", "token", true, "authoriztion token");
        token.setRequired(true);
        options.addOption(token);

        Option action = new Option("a", "action", true, "action");
        action.setRequired(true);
        options.addOption(action);

        Option resource = new Option("r", "resource", true, "resource");
        resource.setRequired(true);
        options.addOption(resource);

        Option conf = new Option("c", "conf", true, "athenz path");
        conf.setRequired(true);
        options.addOption(conf);

        Option policyDir = new Option("p", "policy-dir", true, "policy directory");
        policyDir.setRequired(true);
        options.addOption(policyDir);

        CommandLineParser parser = new DefaultParser();
        HelpFormatter formatter = new HelpFormatter();
        CommandLine cmd = null;

        try {
            cmd = parser.parse(options, args);
        } catch (ParseException e) {
            System.out.println(e.getMessage());
            formatter.printHelp("zpe-check", options);
            System.exit(1);
        }

        return cmd;
    }
}

