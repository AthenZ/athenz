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

import com.yahoo.athenz.instance.provider.InstanceProvider;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.Map;

public class InstanceUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceUtils.class);

    static final String ZTS_CERT_INSTANCE_ID        = ".instanceid.athenz.";
    static final String ZTS_CERT_INSTANCE_ID_URI    = "athenz://instanceid/";

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

    public static boolean validateCertRequestSanDnsNames(final Map<String, String> attributes,
                                                         final String domain, final String service, final String dnsSuffix,
                                                         StringBuilder instanceId) {

        // make sure we have valid dns suffix specified

        if (dnsSuffix == null || dnsSuffix.isEmpty()) {
            LOGGER.error("No Cloud Provider DNS suffix specified for validation");
            return false;
        }

        // first check to see if we're given any san dns names to validate
        // if the list is empty then something is not right thus we'll
        // reject the request

        final String hostnames = InstanceUtils.getInstanceProperty(attributes, InstanceProvider.ZTS_INSTANCE_SAN_DNS);
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

        // we only allow up to two hostnames in our AWS CSR:
        // service.<domain-with-dashes>.<dns-suffix>
        // <instance-id>.instanceid.athenz.<dns-suffix>
        // instance id can be specified as URI

        if (hosts.length > 2) {
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

        // if we have no host entry that it's a failure

        if (!hostCheck) {
            LOGGER.error("Request does not contain expected host SAN DNS entry");
            return false;
        }

        // if there is no instance id field in dnsName check to
        // see if it was passed in the uri as expected

        if (!instanceIdCheck && !validateCertRequestUriId(attributes, instanceId)) {
            LOGGER.error("Request does not contain expected instance id entry");
            return false;
        }

        return true;
    }

    public static boolean validateCertRequestUriId(final Map<String, String> attributes,
            StringBuilder instanceId) {

        // if the list is empty then something is not right thus we'll
        // reject the request

        final String uriList = InstanceUtils.getInstanceProperty(attributes, InstanceProvider.ZTS_INSTANCE_SAN_URI);
        if (uriList == null || uriList.isEmpty()) {
            LOGGER.error("Request contains no SAN URI entries for validation");
            return false;
        }

        String[] uris = uriList.split(",");

        for (String uri : uris) {
            if (!uri.startsWith(ZTS_CERT_INSTANCE_ID_URI)) {
                continue;
            }
            // skip the provider value
            int idx = uri.substring(ZTS_CERT_INSTANCE_ID_URI.length()).indexOf('/');
            if (idx != -1) {
                instanceId.append(uri.substring(ZTS_CERT_INSTANCE_ID_URI.length() + idx + 1));
                return true;
            }
        }

        return false;
    }
}
