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

import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.token.PrincipalToken;
import com.yahoo.athenz.auth.token.Token;
import com.yahoo.athenz.common.server.dns.HostnameResolver;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ResourceException;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.util.*;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class InstanceZTSProvider implements InstanceProvider {


    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceZTSProvider.class);
    private static final Pattern WHITESPACE_PATTERN = Pattern.compile("\\s+");
    private static final String URI_HOSTNAME_PREFIX = "athenz://hostname/";

    static final String ZTS_PROVIDER_DNS_SUFFIX  = "athenz.zts.provider_dns_suffix";
    static final String ZTS_PRINCIPAL_LIST       = "athenz.zts.provider_service_list";

    KeyStore keyStore = null;
    String dnsSuffix = null;
    Set<String> principals = null;
    HostnameResolver hostnameResolver = null;

    @Override
    public Scheme getProviderScheme() {
        return Scheme.CLASS;
    }

    @Override
    public void initialize(String provider, String providerEndpoint, SSLContext sslContext,
            KeyStore keyStore) {

        // obtain list of valid principals for this principal if
        // one is configured

        final String principalList = System.getProperty(ZTS_PRINCIPAL_LIST);
        if (principalList != null && !principalList.isEmpty()) {
            principals = new HashSet<>(Arrays.asList(principalList.split(",")));
        }

        // determine the dns suffix. if this is not specified we'll be
        // rejecting all entries
        
        dnsSuffix = System.getProperty(ZTS_PROVIDER_DNS_SUFFIX, "zts.athenz.cloud");
        if (dnsSuffix.isEmpty()) {
            dnsSuffix = "zts.athenz.cloud";
        }
        this.keyStore = keyStore;
    }

    @Override
    public void setHostnameResolver(HostnameResolver hostnameResolver) {
        this.hostnameResolver = hostnameResolver;
    }

    private ResourceException forbiddenError(String message) {
        LOGGER.error(message);
        return new ResourceException(ResourceException.FORBIDDEN, message);
    }
    
    @Override
    public InstanceConfirmation confirmInstance(InstanceConfirmation confirmation) {

        // we need to validate the token which is our attestation
        // data for the service requesting a certificate

        final String instanceDomain = confirmation.getDomain();
        final String instanceService = confirmation.getService();

        final Map<String, String> instanceAttributes = confirmation.getAttributes();
        final String csrPublicKey = InstanceUtils.getInstanceProperty(instanceAttributes,
                InstanceProvider.ZTS_INSTANCE_CSR_PUBLIC_KEY);

        // make sure this service has been configured to be supported
        // by this zts provider

        if (principals != null && !principals.contains(instanceDomain + "." + instanceService)) {
            throw forbiddenError("Service not supported to be launched by ZTS Provider");
        }

        StringBuilder errMsg = new StringBuilder(256);
        if (!validateToken(confirmation.getAttestationData(), instanceDomain,
                instanceService, csrPublicKey, errMsg)) {
            LOGGER.error(errMsg.toString());
            throw forbiddenError("Unable to validate Certificate Request Auth Token");
        }

        String clientIp = InstanceUtils.getInstanceProperty(instanceAttributes, InstanceProvider.ZTS_INSTANCE_CLIENT_IP);
        String sanIpStr = InstanceUtils.getInstanceProperty(instanceAttributes, InstanceProvider.ZTS_INSTANCE_SAN_IP);
        String hostname = InstanceUtils.getInstanceProperty(instanceAttributes, InstanceProvider.ZTS_INSTANCE_HOSTNAME);
        String sanUri   = InstanceUtils.getInstanceProperty(instanceAttributes, InstanceProvider.ZTS_INSTANCE_SAN_URI);

        // validate the IP address if one is provided

        String[] sanIps = null;
        if (sanIpStr != null && !sanIpStr.isEmpty()) {
            sanIps = sanIpStr.split(",");
        }

        if (!validateSanIp(sanIps, clientIp)) {
            throw forbiddenError("Unable to validate request IP address");
        }

        // validate the hostname in payload
        // IP in clientIP can be NATed. For validating hostname, rely on sanIPs, which come from the client, and are already matched with clientIp

        if (!validateHostname(hostname, sanIps)) {
            throw forbiddenError("Unable to validate certificate request hostname");
        }

        // validate san URI
        if (!validateSanUri(sanUri, hostname)) {
            throw forbiddenError("Unable to validate certificate request URI hostname");
        }

        // validate the certificate san DNS names

        StringBuilder instanceId = new StringBuilder(256);
        if (!InstanceUtils.validateCertRequestSanDnsNames(instanceAttributes, instanceDomain,
                instanceService, dnsSuffix, instanceId)) {
            throw forbiddenError("Unable to validate certificate request DNS");
        }

        // set our cert attributes in the return object
        // for ZTS we do not allow refresh of those certificates

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_CERT_REFRESH, "false");

        confirmation.setAttributes(attributes);
        return confirmation;
    }

    @Override
    public InstanceConfirmation refreshInstance(InstanceConfirmation confirmation) {

        // we do not allow refresh of zts provider certificates
        // the caller should just request a new certificate

        throw forbiddenError("ZTS Provider X.509 Certificates cannot be refreshed");
    }

    /**
     * verifies that at least one of the sanIps matches clientIp
     * @param sanIps
     * @param clientIp
     * @return true if sanIps is null or one of the sanIps matches. false otherwise
     */
    boolean validateSanIp(final String[] sanIps, final String clientIp) {

        LOGGER.debug("Validating sanIps: {}, clientIp: {}", sanIps, clientIp);

        // if we have an IP specified in the CSR, one of the sanIp must match our client IP
        if (sanIps == null || sanIps.length == 0) {
            return true;
        }

        if (clientIp == null || clientIp.isEmpty()) {
            return false;
        }

        // It's possible both ipv4, ipv6 addresses are mentioned in sanIP
        for (String sanIp: sanIps) {
            if (sanIp.equals(clientIp)) {
                return true;
            }
        }

        LOGGER.error("Unable to match sanIp: {} with clientIp:{}", sanIps, clientIp);
        return false;
    }

    /**
     * returns true if an empty hostname attribute is passed
     * returns true if a non-empty hostname attribute is passed and all IPs passed in sanIp match the IPs that hostname resolves to.
     * returns false in all other cases
     * @param hostname
     * @param sanIps
     * @return true or false
     */
    boolean validateHostname(final String hostname, final String[] sanIps) {

        LOGGER.debug("Validating hostname: {}, sanIps: {}", hostname, sanIps);

        if (hostname == null || hostname.isEmpty()) {
            LOGGER.info("Request contains no hostname entry for validation");
            // if more than one sanIp is passed, all sanIPs must map to hostname, and hostname is a must
            if (sanIps != null && sanIps.length > 1) {
                LOGGER.error("SanIps:{} > 1, and hostname is empty", sanIps);
                return false;
            }
            return true;
        }

        // IP in clientIp can be NATed. Rely on sanIp, which comes from the client, and is already matched with clientIp
        // sanIp should be non-empty
        if (sanIps == null || sanIps.length == 0) {
            LOGGER.error("Request contains no sanIp entry for hostname:{} validation", hostname);
            return false;
        }

        // All entries in sanIP must be one of the IPs that hostname resolves
        Set<String>  hostIps = hostnameResolver.getAllByName(hostname);
        for (String sanIp: sanIps) {
            if (!hostIps.contains(sanIp)) {
                LOGGER.error("One of sanIp: {} is not present in HostIps: {}", hostIps, sanIps);
                return false;
            }
        }

        return true;
    }

    /**
     * verifies if sanUri contains athenz://hostname/, the value matches the hostname
     * @param sanUri
     * @param hostname
     * @return
     */
    boolean validateSanUri(final String sanUri, final String hostname) {

        LOGGER.debug("Validating sanUri: {}, hostname: {}", sanUri, hostname);

        if (sanUri == null || sanUri.isEmpty()) {
            LOGGER.info("Request contains no sanURI to verify");
            return true;
        }

        for (String uri: sanUri.split(",")) {
            int idx = uri.indexOf(URI_HOSTNAME_PREFIX);
            if (idx != -1) {
                if (!uri.substring(idx + URI_HOSTNAME_PREFIX.length()).equals(hostname)) {
                    LOGGER.error("SanURI: {} does not contain hostname: {}", sanUri, hostname);
                    return false;
                }
            }
        }

        return true;
    }


    boolean validateToken(final String signedToken, final String domainName,
            final String serviceName, final String csrPublicKey, StringBuilder errMsg) {
        
        final PrincipalToken serviceToken = authenticate(signedToken, keyStore, csrPublicKey, errMsg);
        if (serviceToken == null) {
            return false;
        }
        
        // verify that domain and service name match
        
        if (!serviceToken.getDomain().equalsIgnoreCase(domainName)) {
            errMsg.append("validate failed: domain mismatch: ").
                append(serviceToken.getDomain()).append(" vs. ").append(domainName);
            return false;
        }
        
        if (!serviceToken.getName().equalsIgnoreCase(serviceName)) {
            errMsg.append("validate failed: service mismatch: ").
                append(serviceToken.getName()).append(" vs. ").append(serviceName);
            return false;
        }

        return true;
    }

    PrincipalToken authenticate(final String signedToken, KeyStore keyStore,
            final String csrPublicKey, StringBuilder errMsg) {

        PrincipalToken serviceToken;
        try {
            serviceToken = new PrincipalToken(signedToken);
        } catch (IllegalArgumentException ex) {
            errMsg.append("authenticate failed: Invalid token: exc=").
                    append(ex.getMessage()).append(" : credential=").
                    append(Token.getUnsignedToken(signedToken));
            LOGGER.error(errMsg.toString());
            return null;
        }

        // before authenticating verify that this is not an authorized
        // service token

        if (serviceToken.getAuthorizedServices() != null) {
            errMsg.append("authenticate failed: authorized service token")
                    .append(" : credential=").append(Token.getUnsignedToken(signedToken));
            LOGGER.error(errMsg.toString());
            return null;
        }

        final String tokenDomain = serviceToken.getDomain().toLowerCase();
        final String tokenName = serviceToken.getName().toLowerCase();

        // get the public key for this token to validate signature

        final String publicKey = keyStore.getPublicKey(tokenDomain, tokenName,
                serviceToken.getKeyId());

        if (!serviceToken.validate(publicKey, 300, false, errMsg)) {
            return null;
        }

        // finally we want to make sure the public key in the csr
        // matches the public key registered in Athenz

        if (!validatePublicKeys(publicKey, csrPublicKey)) {
            errMsg.append("CSR and Athenz public key mismatch");
            LOGGER.error(errMsg.toString());
            return null;
        }

        return serviceToken;
    }

    public boolean validatePublicKeys(final String athenzPublicKey, final String csrPublicKey) {

        // we are going to remove all whitespace, new lines
        // in order to compare the pem encoded keys

        Matcher matcher = WHITESPACE_PATTERN.matcher(athenzPublicKey);
        final String normAthenzPublicKey = matcher.replaceAll("");

        matcher = WHITESPACE_PATTERN.matcher(csrPublicKey);
        final String normCsrPublicKey = matcher.replaceAll("");

        return normAthenzPublicKey.equals(normCsrPublicKey);
    }


}
