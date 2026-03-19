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

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.KeyStore;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.token.jwts.JwtsHelper;
import com.yahoo.athenz.auth.token.jwts.JwtsSigningKeyResolver;
import com.yahoo.athenz.common.server.util.config.dynamic.DynamicConfigLong;
import com.yahoo.athenz.instance.provider.InstanceConfirmation;
import com.yahoo.athenz.instance.provider.InstanceProvider;
import com.yahoo.athenz.instance.provider.ProviderResourceException;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import javax.net.ssl.SSLContext;
import java.util.Date;
import java.util.HashMap;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.TimeUnit;

import static com.yahoo.athenz.common.server.util.config.ConfigManagerSingleton.CONFIG_MANAGER;

/**
 * Instance provider for Spacelift, based on its OIDC setup:
 * <ul>
 *     <li><a href="https://docs.spacelift.io/integrations/cloud-providers/oidc">Overview</a></li>
 * </ul>
 */
public class InstanceSpaceliftProvider implements InstanceProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceSpaceliftProvider.class);

    private static final String URI_INSTANCE_ID_PREFIX = "athenz://instanceid/";
    private static final String URI_SPIFFE_PREFIX = "spiffe://";

    static final String SPACELIFT_PROP_PROVIDER_DNS_SUFFIX = "athenz.zts.spacelift.provider_dns_suffix";
    static final String SPACELIFT_PROP_BOOT_TIME_OFFSET    = "athenz.zts.spacelift.boot_time_offset";
    static final String SPACELIFT_PROP_CERT_EXPIRY_TIME    = "athenz.zts.spacelift.cert_expiry_time";
    static final String SPACELIFT_PROP_AUDIENCE            = "athenz.zts.spacelift.audience";
    static final String SPACELIFT_PROP_ISSUER              = "athenz.zts.spacelift.issuer";
    static final String SPACELIFT_PROP_JWKS_URI            = "athenz.zts.spacelift.jwks_uri";

    private static final String CLAIM_SPACE_ID    = "spaceId";
    private static final String CLAIM_CALLER_TYPE = "callerType";
    private static final String CLAIM_CALLER_ID   = "callerId";
    private static final String CLAIM_RUN_TYPE    = "runType";
    private static final String CLAIM_RUN_ID      = "runId";

    Set<String> dnsSuffixes = null;
    String spaceliftIssuer = null;
    String provider = null;
    String audience = null;
    ConfigurableJWTProcessor<SecurityContext> jwtProcessor = null;
    Authorizer authorizer = null;
    DynamicConfigLong bootTimeOffsetSeconds;
    long certExpiryTime;

    @Override
    public Scheme getProviderScheme() {
        return Scheme.CLASS;
    }

    @Override
    public void initialize(String provider, String providerEndpoint, SSLContext sslContext, KeyStore keyStore) {

        // save our provider name

        this.provider = provider;

        // lookup the zts audience. if not specified we'll default to athenz.io

        audience = System.getProperty(SPACELIFT_PROP_AUDIENCE, "athenz.io");

        // determine the dns suffix. if this is not specified we'll just default to spacelift.athenz.io

        final String dnsSuffix = System.getProperty(SPACELIFT_PROP_PROVIDER_DNS_SUFFIX, "spacelift.athenz.io");
        dnsSuffixes = Set.of(dnsSuffix.split(","));

        // how long the instance must be booted in the past before we
        // stop validating the instance requests

        long timeout = TimeUnit.SECONDS.convert(5, TimeUnit.MINUTES);
        bootTimeOffsetSeconds = new DynamicConfigLong(CONFIG_MANAGER, SPACELIFT_PROP_BOOT_TIME_OFFSET, timeout);

        // get default/max expiry time for any generated tokens - 6 hours

        certExpiryTime = Long.parseLong(System.getProperty(SPACELIFT_PROP_CERT_EXPIRY_TIME, "360"));

        // initialize our jwt processor. the issuer is required since
        // spacelift uses per-account issuer urls

        spaceliftIssuer = System.getProperty(SPACELIFT_PROP_ISSUER);
        if (StringUtil.isEmpty(spaceliftIssuer)) {
            throw new IllegalArgumentException("InstanceSpaceliftProvider: Issuer not specified");
        }

        jwtProcessor = JwtsHelper.getJWTProcessor(new JwtsSigningKeyResolver(extractSpaceliftIssuerJwksUri(spaceliftIssuer), null));
    }

    String extractSpaceliftIssuerJwksUri(final String issuer) {

        // if we have the value configured then that's what we're going to use

        final String jwksUri = System.getProperty(SPACELIFT_PROP_JWKS_URI);
        if (!StringUtil.isEmpty(jwksUri)) {
            return jwksUri;
        }

        // otherwise we'll assume the issuer follows the standard and
        // includes the jwks uri in its openid configuration

        final String openIdConfigUri = issuer + "/.well-known/openid-configuration";
        JwtsHelper helper = new JwtsHelper();
        return helper.extractJwksUri(openIdConfigUri, null);
    }

    private ProviderResourceException forbiddenError(String message) {
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

        final String instanceDomain = confirmation.getDomain();
        final String instanceService = confirmation.getService();
        final Map<String, String> instanceAttributes = confirmation.getAttributes();

        // our request must not have any sanIPs or hostnames

        if (!StringUtil.isEmpty(InstanceUtils.getInstanceProperty(instanceAttributes,
                InstanceProvider.ZTS_INSTANCE_SAN_IP))) {
            throw forbiddenError("Request must not have any sanIP addresses");
        }

        if (!StringUtil.isEmpty(InstanceUtils.getInstanceProperty(instanceAttributes,
                InstanceProvider.ZTS_INSTANCE_HOSTNAME))) {
            throw forbiddenError("Request must not have any hostname values");
        }

        // validate san URI

        if (!validateSanUri(InstanceUtils.getInstanceProperty(instanceAttributes,
                InstanceProvider.ZTS_INSTANCE_SAN_URI))) {
            throw forbiddenError("Unable to validate certificate request URI values");
        }

        // we need to validate the token which is our attestation
        // data for the service requesting a certificate

        final String attestationData = confirmation.getAttestationData();
        if (StringUtil.isEmpty(attestationData)) {
            throw forbiddenError("Service credentials not provided");
        }

        StringBuilder errMsg = new StringBuilder(256);
        final String reqInstanceId = InstanceUtils.getInstanceProperty(instanceAttributes,
                InstanceProvider.ZTS_INSTANCE_ID);
        if (!validateOIDCToken(attestationData, instanceDomain, instanceService, reqInstanceId, errMsg)) {
            throw forbiddenError("Unable to validate Certificate Request: " + errMsg);
        }

        // validate the certificate san DNS names

        StringBuilder instanceId = new StringBuilder(256);
        if (!InstanceUtils.validateCertRequestSanDnsNames(instanceAttributes, instanceDomain,
                instanceService, dnsSuffixes, null, null, false, instanceId, null)) {
            throw forbiddenError("Unable to validate certificate request sanDNS entries");
        }

        // set our cert attributes in the return object.
        // for Spacelift we do not allow refresh of those certificates, and
        // the issued certificate can only be used by clients and not servers

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_CERT_REFRESH, "false");
        attributes.put(InstanceProvider.ZTS_CERT_USAGE, ZTS_CERT_USAGE_CLIENT);
        attributes.put(InstanceProvider.ZTS_CERT_EXPIRY_TIME, Long.toString(certExpiryTime));

        confirmation.setAttributes(attributes);
        return confirmation;
    }

    @Override
    public InstanceConfirmation refreshInstance(InstanceConfirmation confirmation) throws ProviderResourceException {

        // we do not allow refresh of Spacelift certificates

        throw forbiddenError("Spacelift X.509 Certificates cannot be refreshed");
    }

    /**
     * verifies that sanUri only contains the spiffe and instance id uris
     * @param sanUri the SAN URI value
     * @return true if it only contains spiffe and instance id uris, otherwise false
     */
    boolean validateSanUri(final String sanUri) {

        if (StringUtil.isEmpty(sanUri)) {
            LOGGER.debug("Request contains no sanURI to verify");
            return true;
        }

        for (String uri: sanUri.split(",")) {
            if (uri.startsWith(URI_SPIFFE_PREFIX) || uri.startsWith(URI_INSTANCE_ID_PREFIX)) {
                continue;
            }
            LOGGER.error("Request contains unsupported uri value: {}", uri);
            return false;
        }

        return true;
    }

    boolean validateOIDCToken(final String jwToken, final String domainName, final String serviceName,
            final String instanceId, StringBuilder errMsg) {

        if (jwtProcessor == null) {
            errMsg.append("JWT Processor not initialized");
            return false;
        }

        JWTClaimsSet claimsSet;
        try {
            claimsSet = jwtProcessor.process(jwToken, null);
        } catch (Exception ex) {
            errMsg.append("Unable to parse and validate token: ").append(ex.getMessage());
            return false;
        }

        // verify the issuer is set to Spacelift

        if (!spaceliftIssuer.equals(claimsSet.getIssuer())) {
            errMsg.append("token issuer is not Spacelift: ").append(claimsSet.getIssuer());
            return false;
        }

        // verify that token audience is set for our service

        if (!audience.equals(JwtsHelper.getAudience(claimsSet))) {
            errMsg.append("token audience is not ZTS Server audience: ").append(JwtsHelper.getAudience(claimsSet));
            return false;
        }

        // need to verify that the issue time is within our configured bootstrap time

        Date issueDate = claimsSet.getIssueTime();
        if (issueDate == null || issueDate.getTime() < System.currentTimeMillis() -
                TimeUnit.SECONDS.toMillis(bootTimeOffsetSeconds.get())) {
            errMsg.append("job start time is not recent enough, issued at: ").append(issueDate);
            return false;
        }

        // verify that the instance id matches the claims in the token

        if (!validateInstanceId(instanceId, claimsSet, errMsg)) {
            return false;
        }

        // verify the domain and service names in the token based on our configuration

        return validateTenantDomainToken(claimsSet, domainName, serviceName, errMsg);
    }

    boolean validateInstanceId(final String instanceId, final JWTClaimsSet claimsSet, StringBuilder errMsg) {

        // the format for our instance id is <spaceId>:<callerId>:<runId>

        final String spaceId = JwtsHelper.getStringClaim(claimsSet, CLAIM_SPACE_ID);
        if (StringUtil.isEmpty(spaceId)) {
            errMsg.append("token does not contain required ").append(CLAIM_SPACE_ID).append(" claim");
            return false;
        }
        final String callerId = JwtsHelper.getStringClaim(claimsSet, CLAIM_CALLER_ID);
        if (StringUtil.isEmpty(callerId)) {
            errMsg.append("token does not contain required ").append(CLAIM_CALLER_ID).append(" claim");
            return false;
        }
        final String runId = JwtsHelper.getStringClaim(claimsSet, CLAIM_RUN_ID);
        if (StringUtil.isEmpty(runId)) {
            errMsg.append("token does not contain required ").append(CLAIM_RUN_ID).append(" claim");
            return false;
        }

        final String tokenInstanceId = spaceId + ":" + callerId + ":" + runId;
        if (!tokenInstanceId.equals(instanceId)) {
            errMsg.append("invalid instance id: ").append(tokenInstanceId).append("/").append(instanceId);
            return false;
        }
        return true;
    }

    boolean validateTenantDomainToken(final JWTClaimsSet claimsSet, final String domainName, final String serviceName,
            StringBuilder errMsg) {

        // we need to generate our resource value based on the subject

        final String subject = claimsSet.getSubject();
        if (StringUtil.isEmpty(subject)) {
            errMsg.append("token does not contain required subject claim");
            return false;
        }

        // generate our principal object and carry out authorization check

        final String resource = domainName + ":" + subject;
        Principal principal = SimplePrincipal.create(domainName, serviceName, (String) null);

        // Spacelift has no event/action type; instead, the user must configure policies based
        // on the subject claim which includes space, stack/module, run_type, and scope.
        // e.g., 'space:<SPACE>:stack:<STACK>:run_type:TRACKED:scope:write'
        // vs 'space:<SPACE>:stack:<STACK>:run_type:*:scope:*' for broader access.

        final String action = "spacelift.run";
        if (!authorizer.access(action, resource, principal, null)) {
            errMsg.append("authorization check failed for action ").append(action).append(", resource: ").append(resource);
            return false;
        }
        return true;
    }
}
