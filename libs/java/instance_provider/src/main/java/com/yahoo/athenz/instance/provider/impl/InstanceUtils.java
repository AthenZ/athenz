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

import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class InstanceUtils {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceUtils.class);

    static final String ZTS_CERT_INSTANCE_ID      = ".instanceid.athenz.";
    static final int ZTS_CERT_INSTANCE_ID_LEN     = ZTS_CERT_INSTANCE_ID.length();

    static final String ZTS_CERT_INSTANCE_ID_URI  = "athenz://instanceid/";
    static final int ZTS_CERT_INSTANCE_ID_URI_LEN = ZTS_CERT_INSTANCE_ID_URI.length();

    static final String ZTS_CERT_INSTANCE_NAME_URI = "athenz://instancename/";

    static final String URL_REGEX = "^https://([^/?]+)";
    static final Pattern URL_PATTERN = java.util.regex.Pattern.compile(URL_REGEX);

    static final String K8S_SERVICE_ACCOUNT_PREFIX = "system:serviceaccount:";

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

    static int dnsSuffixMatchIndex(final String hostname, final List<String> dnsSuffixes) {
        for (String dnsSuffix : dnsSuffixes) {
            if (hostname.endsWith(dnsSuffix)) {
                return hostname.length() - dnsSuffix.length();
            }
        }
        return -1;
    }

    static List<String> processK8SDnsSuffixList(final String propertyName) {

        List<String> k8sDnsSuffixes = new ArrayList<>();
        final String k8sDnsSuffix = System.getProperty(propertyName);
        if (StringUtil.isEmpty(k8sDnsSuffix)) {
            LOGGER.info("K8S DNS Suffix not specified - all requests must satisfy standard dns suffix checks");
        } else {
            // in our checks we're going to match against the given suffix so
            // when generating the list we'll verify if the suffix starts with
            // . or not. If not, we'll automatically add one
            String[] k8sDnsList = k8sDnsSuffix.split(",");
            for (String k8sDns : k8sDnsList) {
                if (StringUtil.isEmpty(k8sDns)) {
                    continue;
                }
                if (k8sDns.charAt(0) == '.') {
                    k8sDnsSuffixes.add(k8sDns);
                } else {
                    k8sDnsSuffixes.add("." + k8sDns);
                }
            }
        }
        return k8sDnsSuffixes;
    }

    static boolean k8sDnsSuffixCheck(final String hostname, final List<String> dnsSuffixes) {

        // it's possible that we don't have k8s dns suffix list provided

        if (dnsSuffixes == null) {
            return false;
        }

        // a) the sanDNS entry must one with <k8sDnsSuffix> e.g. svc.cluster.local
        // b) the prefix must contain at least 2 components based on k8s dns spec

        for (String dnsSuffix : dnsSuffixes) {
            if (hostname.endsWith(dnsSuffix)) {
                int idx = hostname.length() - dnsSuffix.length();
                final String prefix = hostname.substring(0, idx);
                if (prefix.chars().filter(ch -> ch == '.').count() > 0) {
                    return true;
                }
            }
        }
        return false;
    }

    static boolean validateSanDnsName(final String hostname, final String service, final List<String> dnsSuffixes,
                                      final List<String> k8sDnsSuffixes, final Set<String> clusterNameSet) {

        // for hostnames that are included in the sanDNS entry in the certificate we have
        // a couple of requirements:
        // Option 1: cluster based san dns entry
        // a) the format is <service>.<domain-with-dashes>.<cluster>.<dnsSuffix>
        // Option 2: k8s dns entry
        // a) the sanDNS entry must end with <k8sDnsSuffix> e.g. svc.cluster.local
        // b) the prefix must contain at least 2 components based on k8s dns spec
        // Option 3
        // a) the sanDNS entry must end with <domain-with-dashes>.<dnsSuffix>
        // b) one of the prefix components must be the <service> name

        // let's first verify if this is a cluster based san dns entry since
        // that is a quick check against our set

        if (clusterNameSet != null && clusterNameSet.contains(hostname)) {
            return true;
        }

        // next, let's verify if this is a k8s dns entry

        if (k8sDnsSuffixCheck(hostname, k8sDnsSuffixes)) {
            return true;
        }

        // if not, then let's verify that we have an expected dns-suffix

        int suffixIdx = dnsSuffixMatchIndex(hostname, dnsSuffixes);
        if (suffixIdx == -1) {
            LOGGER.error("{} does not end with expected dns suffix value", hostname);
            return false;
        }

        // extract the prefix component of the dns name

        final String prefix = hostname.substring(0, suffixIdx);
        for (String comp : prefix.split("\\.")) {
            if (service.equals(comp)) {
                return true;
            }
        }

        LOGGER.error("{} does not include required service name {} component", hostname, service);
        return false;
    }

    /**
     * validate the specifies sanDNS entries in the certificate request. If the failedDnsNames
     * list is specified, it will be populated with the dns names that failed validation.
     * However, if the failure is critical (e.g. we couldn't validate hostname, dns names suffix
     * list is not specified), then the method will return false and the failedDnsNames list
     * will be empty.
     * @param attributes attributes from the certificate request
     * @param domain name of the domain
     * @param service name of the service
     * @param dnsSuffixes list of dns suffixes
     * @param k8sDnsSuffixes list of k8s dns suffixes
     * @param k8sClusterNames list of k8s cluster names
     * @param validateHostname flag to indicate whether we should validate hostname
     * @param instanceId instance id value to be returned
     * @param failedDnsNames list of failed dns names to be returned
     * @return true if all dns names are valid, false otherwise
     */
    public static boolean validateCertRequestSanDnsNames(final Map<String, String> attributes, final String domain,
            final String service, final Set<String> dnsSuffixes, final List<String> k8sDnsSuffixes,
            final List<String> k8sClusterNames, boolean validateHostname, StringBuilder instanceId,
            List<String> failedDnsNames) {

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

        // for hostnames that are included in the sanDNS entry in the certificate we have
        // a couple of requirements:
        // a) the sanDNS entry must end with <domain-with-dashes>.<dnsSuffix>
        // b) one of the prefix components must be the <service> name

        List<String> hostNameSuffixList = new ArrayList<>();
        final String dashDomain = domain.replace('.', '-');
        for (String dnsSuffix : dnsSuffixes) {
            hostNameSuffixList.add("." + dashDomain + "." + dnsSuffix);
        }

        // generate our cluster based names if we have clusters configured

        Set<String> clusterNameSet = null;
        if (k8sClusterNames != null && !k8sClusterNames.isEmpty()) {
            clusterNameSet = new HashSet<>();
            for (String clusterName : k8sClusterNames) {
                for (String dnsSuffix : dnsSuffixes) {
                    clusterNameSet.add(service + "." + dashDomain + "." + clusterName + "." + dnsSuffix);
                }
            }
        }

        // if we have a hostname configured then verify it matches one of formats

        if (validateHostname) {
            final String hostname = InstanceUtils.getInstanceProperty(attributes, InstanceProvider.ZTS_INSTANCE_HOSTNAME);
            if (!StringUtil.isEmpty(hostname) && !validateSanDnsName(hostname, service, hostNameSuffixList, k8sDnsSuffixes, clusterNameSet)) {
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

            if (!validateSanDnsName(host, service, hostNameSuffixList, k8sDnsSuffixes, clusterNameSet)) {

                // if we're not interested in the list of failed hostnames then
                // we'll return failure right away. otherwise we'll keep track
                // of the failed hostname and continue with the rest of the list

                if (failedDnsNames == null) {
                    return false;
                } else {
                    failedDnsNames.add(host);
                    continue;
                }
            }

            hostCheck = true;
        }

        // if we have no host entry that it's a failure. We're going to
        // make sure the failedDnsNames list is empty and return false
        // so the caller knows this is a critical failure as opposed to
        // failure of not being able to validate the specified entries

        if (!hostCheck) {
            LOGGER.error("Request does not contain expected host SAN DNS entry");
            if (failedDnsNames != null) {
                failedDnsNames.clear();
            }
            return false;
        }

        // if we got here, then we're good to go as long as the
        // failedDnsNames list is empty or null.
        // if it's not empty then we have some failed entries
        // and if it's null, then we would have already returned
        // failure when processing the list

        return failedDnsNames == null || failedDnsNames.isEmpty();
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

    public static String extractURLDomainName(final String url) {

        if (StringUtil.isEmpty(url)) {
            return null;
        }
        Matcher matcher = URL_PATTERN.matcher(url);
        if (matcher.find()) {
            return matcher.group(1);
        }
        // Return null if no domain name found
        return null;
    }

    public static String getServiceAccountNameFromIdTokenSubject(final String sub) {
        if (StringUtil.isEmpty(sub) || !sub.startsWith(K8S_SERVICE_ACCOUNT_PREFIX)) {
            return null;
        }
        String[] components = sub.split(":");
        if (components.length != 4) {
            return null;
        }
        return components[3];
    }
}
