/*
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
package com.yahoo.athenz.instance.provider.impl;

import com.yahoo.athenz.instance.provider.InstanceProvider;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.util.HashSet;
import java.util.Map;
import java.util.Set;

public class InstanceUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceUtils.class);

    static final String ZTS_CERT_INSTANCE_ID      = ".instanceid.athenz.";
    static final int ZTS_CERT_INSTANCE_ID_LEN     = ZTS_CERT_INSTANCE_ID.length();

    static final String ZTS_CERT_INSTANCE_ID_URI  = "athenz://instanceid/";
    static final int ZTS_CERT_INSTANCE_ID_URI_LEN = ZTS_CERT_INSTANCE_ID_URI.length();

    public static String getInstanceProperty(final Map<String, String> attributes,
            final String propertyName) {

        if (attributes == null) {
            LOGGER.debug("getInstanceProperty: no attributes available");
            return null;
        }

        final String value = attributes.get(propertyName);
        if (value == null) {
            LOGGER.debug("getInstanceProperty: {} attribute not available", propertyName);
            return null;
        }

        return value;
    }

    public static boolean validateCertRequestSanDnsNames(final Map<String, String> attributes, final String domain,
            final String service, final Set<String> dnsSuffixes, boolean validateHostname, StringBuilder instanceId) {

        // make sure we have valid dns suffix specified

        if (dnsSuffixes == null || dnsSuffixes.isEmpty()) {
            LOGGER.error("No Cloud Provider DNS suffix specified for validation");
            return false;
        }

        // first check to see if we're given any san dns names to validate
        // if the list is empty then something is not right thus we'll
        // reject the request

        final String hostnames = InstanceUtils.getInstanceProperty(attributes, InstanceProvider.ZTS_INSTANCE_SAN_DNS);
        if (StringUtil.isEmpty(hostnames)) {
            LOGGER.error("Request contains no SAN DNS entries for validation");
            return false;
        }
        String[] hosts = hostnames.split(",");

        // extract the instance id from the request

        if (!extractCertRequestInstanceId(attributes, hosts, dnsSuffixes, instanceId)) {
            LOGGER.error("Request does not contain expected instance id entry");
            return false;
        }

        // generate the expected hostname(s) for check. we support two formats:
        // service based hostname: <service>.<domain-with-dashes>.<dnsSuffix>
        // instance id based hostname: <instance-id>.<service>.<domain-with-dashes>.<dnsSuffix>

        Set<String> hostNameChecks = new HashSet<>();
        final String dashDomain = domain.replace('.', '-');
        for (String dnsSuffix : dnsSuffixes) {
            final String hostname = service + "." + dashDomain + "." + dnsSuffix;
            hostNameChecks.add(hostname);
            hostNameChecks.add(instanceId + "." + hostname);
        }

        // if we have a hostname configured then verify it matches one of formats

        if (validateHostname) {
            final String hostname = InstanceUtils.getInstanceProperty(attributes, InstanceProvider.ZTS_INSTANCE_HOSTNAME);
            if (!StringUtil.isEmpty(hostname) && !hostNameChecks.contains(hostname)) {
                LOGGER.error("Request contains an invalid hostname: {}", hostname);
                return false;
            }
        }

        // validate the entries in our san dns list

        boolean hostCheck = false;
        for (String host : hosts) {

            // ignore any entries used for instance id since we've processed
            // those already when looking for the instance id

            if (host.contains(ZTS_CERT_INSTANCE_ID)) {
                continue;
            }

            if (!hostNameChecks.contains(host)) {
                LOGGER.error("Unable to verify SAN DNS entry: {}", host);
                return false;
            }

            hostCheck = true;
        }

        // if we have no host entry that it's a failure

        if (!hostCheck) {
            LOGGER.error("Request does not contain expected host SAN DNS entry");
            return false;
        }

        return true;
    }

    private static boolean extractCertRequestInstanceId(final Map<String, String> attributes, final String[] hosts,
            final Set<String> dnsSuffixes, StringBuilder instanceId) {

        for (String host : hosts) {

            int idx = host.indexOf(ZTS_CERT_INSTANCE_ID);
            if (idx != -1) {

                // verify that we already don't have an instance id specified

                if (instanceId.length() != 0) {
                    LOGGER.error("Multiple instance id values specified: {}, {}", host, instanceId);
                    return false;
                }

                if (!dnsSuffixes.contains(host.substring(idx + ZTS_CERT_INSTANCE_ID_LEN))) {
                    LOGGER.error("Host: {} does not have expected instance id format", host);
                    return false;
                }

                instanceId.append(host, 0, idx);
            }
        }

        // if we found a value from our dns name values then we return right away
        // otherwise, we need to look at the uri values to extract the instance id

        if (instanceId.length() != 0) {
            return true;
        } else {
            return extractCertRequestUriId(attributes, instanceId);
        }
    }

    public static boolean extractCertRequestUriId(final Map<String, String> attributes,
            StringBuilder instanceId) {

        // if the list is empty then something is not right thus we'll
        // reject the request

        final String uriList = InstanceUtils.getInstanceProperty(attributes, InstanceProvider.ZTS_INSTANCE_SAN_URI);
        if (StringUtil.isEmpty(uriList)) {
            LOGGER.error("Request contains no SAN URI entries for validation");
            return false;
        }

        String[] uris = uriList.split(",");
        for (String uri : uris) {

            if (!uri.startsWith(ZTS_CERT_INSTANCE_ID_URI)) {
                continue;
            }

            // skip the provider value but take into account the case
            // where there is no value specified after provider /

            int idx = uri.indexOf('/', ZTS_CERT_INSTANCE_ID_URI_LEN);
            if (idx != -1) {
                final String id = uri.substring(idx + 1);
                if (id.isEmpty()) {
                    LOGGER.error("Empty instance uri provided in uri: {}", uri);
                    return false;
                }
                instanceId.append(id);
                return true;
            }
        }

        return false;
    }
}
