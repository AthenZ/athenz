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

    static final String ZTS_PROVIDER_DNS_SUFFIX  = "athenz.zts.provider_dns_suffix";
    static final String ZTS_PRINCIPAL_LIST       = "athenz.zts.provider_service_list";

    KeyStore keyStore = null;
    String dnsSuffix = null;
    Set<String> principals = null;

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
                InstanceUtils.ZTS_INSTANCE_CSR_PUBLIC_KEY);

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

        // validate the certificate host names
        
        StringBuilder instanceId = new StringBuilder(256);
        if (!InstanceUtils.validateCertRequestHostnames(instanceAttributes, instanceDomain,
                instanceService, dnsSuffix, instanceId)) {
            throw forbiddenError("Unable to validate certificate request hostnames");
        }

        // validate the IP address if one is provided

        if (!validateIPAddress(InstanceUtils.getInstanceProperty(instanceAttributes, InstanceUtils.ZTS_INSTANCE_CLIENT_IP),
                InstanceUtils.getInstanceProperty(instanceAttributes, InstanceUtils.ZTS_INSTANCE_SAN_IP))) {
            throw forbiddenError("Unable to validate request IP address");
        }

        // set our cert attributes in the return object
        // for ZTS we do not allow refresh of those certificates

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceUtils.ZTS_CERT_REFRESH, "false");

        confirmation.setAttributes(attributes);
        return confirmation;
    }

    @Override
    public InstanceConfirmation refreshInstance(InstanceConfirmation confirmation) {
        
        // we do not allow refresh of zts provider certificates
        // the caller should just request a new certificate

        throw forbiddenError("ZTS Provider X.509 Certificates cannot be refreshed");
    }

    boolean validateIPAddress(final String clientIP, final String sanIPs) {

        // if we have an IP specified in the CSR, it must match our client IP

        if (sanIPs == null || sanIPs.isEmpty()) {
            return true;
        }

        return (sanIPs.equals(clientIP));
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
