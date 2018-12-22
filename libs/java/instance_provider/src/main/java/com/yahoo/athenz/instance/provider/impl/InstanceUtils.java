/*
 * Copyright 2018 Oath, Inc.
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
package com.yahoo.athenz.instance.provider.impl;

import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

public class InstanceUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceUtils.class);

    static final String ZTS_CERT_USAGE              = "certUsage";
    static final String ZTS_CERT_EXPIRY_TIME        = "certExpiryTime";
    static final String ZTS_CERT_SSH                = "certSSH";
    static final String ZTS_CERT_USAGE_CLIENT       = "client";
    static final String ZTS_CERT_REFRESH            = "certRefresh";

    static final String ZTS_CERT_INSTANCE_ID        = ".instanceid.athenz.";
    static final String ZTS_INSTANCE_SAN_DNS        = "sanDNS";
    static final String ZTS_INSTANCE_SAN_IP         = "sanIP";
    static final String ZTS_INSTANCE_CLIENT_IP      = "clientIP";
    static final String ZTS_INSTANCE_ID             = "instanceId";
    static final String ZTS_INSTANCE_CSR_PUBLIC_KEY = "csrPublicKey";

    public static String getInstanceProperty(final Map<String, String> attributes,
            final String propertyName) {

        if (attributes == null) {
            LOGGER.error("getInstanceProperty: no attributes available");
            return null;
        }

        final String value = attributes.get(propertyName);
        if (value == null) {
            LOGGER.error("getInstanceProperty: " + propertyName + " attribute not available");
            return null;
        }

        return value;
    }

    public static boolean validateCertRequestHostnames(final Map<String, String> attributes,
            final String domain, final String service, final String dnsSuffix,
            StringBuilder instanceId) {

        // make sure we have valid dns suffix specified

        if (dnsSuffix == null || dnsSuffix.isEmpty()) {
            LOGGER.error("No AWS DNS suffix specified for validation");
            return false;
        }

        // first check to see if we're given any hostnames to validate
        // if the list is empty then something is not right thus we'll
        // reject the request

        final String hostnames = InstanceUtils.getInstanceProperty(attributes, ZTS_INSTANCE_SAN_DNS);
        if (hostnames == null || hostnames.isEmpty()) {
            LOGGER.error("Request contains no SAN DNS entries for validation");
            return false;
        }

        // generate the expected hostname for check

        final String hostNameCheck = service + "." + domain.replace('.', '-') + "." + dnsSuffix;

        // validate the entries

        boolean hostCheck = false;
        boolean instanceIdCheck = false;

        String[] hosts = hostnames.split(",");

        // we only allow two hostnames in our AWS CSR:
        // service.<domain-with-dashes>.<dns-suffix>
        // <instance-id>.instanceid.athenz.<dns-suffix>

        if (hosts.length != 2) {
            LOGGER.error("Request does not contain expected number of SAN DNS entries: {}",
                    hosts.length);
            return false;
        }

        for (String host : hosts) {

            int idx = host.indexOf(ZTS_CERT_INSTANCE_ID);
            if (idx != -1) {
                instanceId.append(host, 0, idx);
                if (!dnsSuffix.equals(host.substring(idx + ZTS_CERT_INSTANCE_ID.length()))) {
                    LOGGER.error("Host: {} does not have expected instance id format", host);
                    return false;
                }

                instanceIdCheck = true;
            } else {
                if (!hostNameCheck.equals(host)) {
                    LOGGER.error("Unable to verify SAN DNS entry: {}", host);
                    return false;
                }
                hostCheck = true;
            }
        }

        // report error cases separately for easier debugging

        if (!instanceIdCheck) {
            LOGGER.error("Request does not contain expected instance id SAN DNS entry");
            return false;
        }

        if (!hostCheck) {
            LOGGER.error("Request does not contain expected host SAN DNS entry");
            return false;
        }

        return true;
    }
}
