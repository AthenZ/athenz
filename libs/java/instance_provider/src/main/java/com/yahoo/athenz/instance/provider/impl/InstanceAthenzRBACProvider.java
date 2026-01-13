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

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.util.Crypto;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ProviderResourceException;
import org.bouncycastle.asn1.x500.style.BCStyle;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import javax.security.auth.x500.X500Principal;
import java.util.*;
import java.util.stream.Collectors;

public class InstanceAthenzRBACProvider implements InstanceProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceAthenzRBACProvider.class);

    static final String ZTS_PROP_ATHENZ_RBAC_ISSUER_DN_LIST = "athenz.zts.athenz_rbac_provider_issuer_dn_list";
    static final String ATHENZ_RBAC_ACTION = "zts.assume_service";

    String provider = null;
    Authorizer authorizer = null;
    Set<String> issuerDNs = null;

    @Override
    public Scheme getProviderScheme() {
        return Scheme.CLASS;
    }

    @Override
    public SVIDType getSVIDType() {
        return SVIDType.JWT;
    }

    @Override
    public void initialize(String provider, String providerEndpoint, SSLContext sslContext,
            KeyStore keyStore) {

        // save our provider name

        this.provider = provider;

        final String issuerList = System.getProperty(ZTS_PROP_ATHENZ_RBAC_ISSUER_DN_LIST);
        if (!StringUtil.isEmpty(issuerList)) {
            issuerDNs = parseDnList(Arrays.asList(issuerList.split(";")));
        }
    }

    Set<String> parseDnList(List<String> list) {
        return list.stream()
                .map(dn -> new X500Principal(dn).getName())
                .collect(Collectors.toSet());
    }

    ProviderResourceException forbiddenError(String message) {
        LOGGER.error(message);
        return new ProviderResourceException(ProviderResourceException.FORBIDDEN, message);
    }

    @Override
    public void setAuthorizer(Authorizer authorizer) {
        this.authorizer = authorizer;
    }

    @Override
    public InstanceConfirmation confirmInstance(InstanceConfirmation confirmation) throws ProviderResourceException {

        // before running any checks make sure we have a valid authorizer

        if (authorizer == null) {
            throw forbiddenError("Authorizer not available");
        }

        final String domainName = confirmation.getDomain();
        final String serviceName = confirmation.getService();
        final Map<String, String> instanceAttributes = confirmation.getAttributes();

        // validate that the request is from a known issuer

        if (!validateIssuer(instanceAttributes)) {
            throw forbiddenError("Invalid issuer DN");
        }

        // extract the certificate dn and extract the cn

        final String dn = InstanceUtils.getInstanceProperty(instanceAttributes, InstanceProvider.ZTS_INSTANCE_CERT_SUBJECT_DN);
        if (StringUtil.isEmpty(dn)) {
            throw forbiddenError("No certificate subject DN provided");
        }

        final String clientIdentity = Crypto.extractX500DnField(dn, BCStyle.CN);
        if (StringUtil.isEmpty(clientIdentity)) {
            throw forbiddenError("Unable to extract certificate subject CN from DN: " + dn);
        }
        int index = clientIdentity.lastIndexOf('.');
        if (index == -1) {
            throw forbiddenError("Invalid certificate subject CN: " + clientIdentity);
        }
        final String clientDomain = clientIdentity.substring(0, index);
        final String clientService = clientIdentity.substring(index + 1);
        if (clientDomain.isEmpty() || clientService.isEmpty()) {
            throw forbiddenError("Invalid certificate subject CN: " + clientIdentity);
        }

        // carry out our authorization check to see if the given principal
        // is authorized to assume the given service identity

        final String resource = domainName + ":service." + serviceName;
        Principal principal = SimplePrincipal.create(clientDomain, clientService, (String) null);
        boolean accessCheck = authorizer.access(ATHENZ_RBAC_ACTION, resource, principal, null);
        if (!accessCheck) {
            throw forbiddenError("Service: " + clientIdentity + " not authorized to assume identity: "
                    + domainName + "." + serviceName);
        }

        return confirmation;
    }

    @Override
    public InstanceConfirmation refreshInstance(InstanceConfirmation confirmation) throws ProviderResourceException {
        throw forbiddenError("JWT SVIDs cannot be refreshed");
    }

    /**
     * validateIssuer ensures that IssuerDN is passed in.
     * If issuerDNs is configured, it validates the IssuerDN against the configured values
     * @param attributes map of attributes passed by ZTS
     * @return true if the issuer dn is in our configured list
     */
    boolean validateIssuer(final Map<String, String> attributes) {

        final String dn = InstanceUtils.getInstanceProperty(attributes, InstanceProvider.ZTS_INSTANCE_CERT_ISSUER_DN);
        if (StringUtil.isEmpty(dn)) {
            LOGGER.error("issuer DN must be passed by ZTS");
            return false;
        }

        // If no allow list configured, accept any issuer

        if (issuerDNs == null) {
            return true;
        }

        return issuerDNs.contains(dn);
    }
}
