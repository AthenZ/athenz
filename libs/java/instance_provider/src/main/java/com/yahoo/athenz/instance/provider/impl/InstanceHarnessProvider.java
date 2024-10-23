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
import java.util.*;
import java.util.concurrent.TimeUnit;

import static com.yahoo.athenz.common.server.util.config.ConfigManagerSingleton.CONFIG_MANAGER;

public class InstanceHarnessProvider implements InstanceProvider {

    private static final Logger LOGGER = LoggerFactory.getLogger(InstanceHarnessProvider.class);

    private static final String URI_INSTANCE_ID_PREFIX = "athenz://instanceid/";
    private static final String URI_SPIFFE_PREFIX = "spiffe://";

    static final String HARNESS_PROP_PROVIDER_DNS_SUFFIX  = "athenz.zts.harness.provider_dns_suffix";
    static final String HARNESS_PROP_BOOT_TIME_OFFSET     = "athenz.zts.harness.boot_time_offset";
    static final String HARNESS_PROP_CERT_EXPIRY_TIME     = "athenz.zts.harness.cert_expiry_time";
    static final String HARNESS_PROP_ACCOUNT_ID           = "athenz.zts.harness.account_id";
    static final String HARNESS_PROP_AUDIENCE             = "athenz.zts.harness.audience";
    static final String HARNESS_PROP_ISSUER               = "athenz.zts.harness.issuer";
    static final String HARNESS_PROP_JWKS_URI             = "athenz.zts.harness.jwks_uri";

    public static final String CLAIM_ACCOUNT_ID      = "account_id";
    public static final String CLAIM_ORGANIZATION_ID = "organization_id";
    public static final String CLAIM_PROJECT_ID      = "project_id";
    public static final String CLAIM_PIPELINE_ID     = "pipeline_id";
    public static final String CLAIM_CONTEXT         = "context";

    public static final String CONTEXT_TRIGGER_EVENT   = "triggerEvent";
    public static final String CONTEXT_TRIGGER_TYPE    = "triggerType";
    public static final String CONTEXT_TRIGGER_ID_NULL = "null";
    public static final String CONTEXT_SEQUENCE_ID     = "sequenceId";

    Set<String> dnsSuffixes = null;
    String harnessIssuer = null;
    String provider = null;
    String audience = null;
    String accountId = null;
    ConfigurableJWTProcessor<SecurityContext> jwtProcessor = null;
    Authorizer authorizer = null;
    DynamicConfigLong bootTimeOffsetSeconds;
    long certExpiryTime;

    @Override
    public Scheme getProviderScheme() {
        return Scheme.CLASS;
    }

    @Override
    public void initialize(String provider, String providerEndpoint, SSLContext sslContext,
            KeyStore keyStore) {

        // save our provider name

        this.provider = provider;

        // lookup the zts audience. if not specified we'll default to athenz.io

        audience = System.getProperty(HARNESS_PROP_AUDIENCE, "athenz.io");

        // determine the dns suffix. if this is not specified we'll just default to harness.athenz.io

        final String dnsSuffix = System.getProperty(HARNESS_PROP_PROVIDER_DNS_SUFFIX, "harness.athenz.io");
        dnsSuffixes = new HashSet<>();
        dnsSuffixes.addAll(Arrays.asList(dnsSuffix.split(",")));

        // how long the instance must be booted in the past before we
        // stop validating the instance requests

        long timeout = TimeUnit.SECONDS.convert(5, TimeUnit.MINUTES);
        bootTimeOffsetSeconds = new DynamicConfigLong(CONFIG_MANAGER, HARNESS_PROP_BOOT_TIME_OFFSET, timeout);

        // determine the account id for the provider

        accountId = System.getProperty(HARNESS_PROP_ACCOUNT_ID);

        // get default/max expiry time for any generated tokens - 6 hours

        certExpiryTime = Long.parseLong(System.getProperty(HARNESS_PROP_CERT_EXPIRY_TIME, "360"));

        // initialize our jwt processor

        harnessIssuer = System.getProperty(HARNESS_PROP_ISSUER);
        if (StringUtil.isEmpty(harnessIssuer)) {
            throw new IllegalArgumentException("InstanceHarnessProvider: Issuer not specified");
        }

        jwtProcessor = JwtsHelper.getJWTProcessor(new JwtsSigningKeyResolver(extractHarnessIssuerJwksUri(harnessIssuer), null));
    }

    String extractHarnessIssuerJwksUri(final String issuer) {

        // if we have the value configured then that's what we're going to use

        final String jwksUri = System.getProperty(HARNESS_PROP_JWKS_URI);
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
        // for Harness, we do not allow refresh of those certificates, and
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

        // we do not allow refresh of Harness certificates

        throw forbiddenError("Harness X.509 Certificates cannot be refreshed");
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

        // verify the issuer in set to Harness

        if (!harnessIssuer.equals(claimsSet.getIssuer())) {
            errMsg.append("token issuer is not Harness: ").append(claimsSet.getIssuer());
            return false;
        }

        // verify that token audience is set for our service

        if (!audience.equals(JwtsHelper.getAudience(claimsSet))) {
            errMsg.append("token audience is not ZTS Server audience: ").append(JwtsHelper.getAudience(claimsSet));
            return false;
        }

        // verify that token issuer is set for our organization if one is configured

        if (!StringUtil.isEmpty(accountId)) {
            final String tokenAccountId = JwtsHelper.getStringClaim(claimsSet, CLAIM_ACCOUNT_ID);
            if (!accountId.equals(tokenAccountId)) {
                errMsg.append("token account id is not the configured account id: ").append(tokenAccountId);
                return false;
            }
        }

        // need to verify that the issue time is within our configured bootstrap time

        Date issueDate = claimsSet.getIssueTime();
        if (issueDate == null || issueDate.getTime() < System.currentTimeMillis() -
                TimeUnit.SECONDS.toMillis(bootTimeOffsetSeconds.get())) {
            errMsg.append("job start time is not recent enough, issued at: ").append(issueDate);
            return false;
        }

        // verify that the instance id matches the repository and run id in the token

        if (!validateInstanceId(instanceId, claimsSet, errMsg)) {
            return false;
        }

        // verify the domain and service names in the token based on our configuration

        return validateTenantDomainToken(claimsSet, domainName, serviceName, errMsg);
    }

    boolean validateInstanceId(final String instanceId, JWTClaimsSet claimsSet, StringBuilder errMsg) {

        // extract the account, organization, project and pipeline ids from the subject

        final String tokenOrganizationId = JwtsHelper.getStringClaim(claimsSet, CLAIM_ORGANIZATION_ID);
        final String tokenProjectId = JwtsHelper.getStringClaim(claimsSet, CLAIM_PROJECT_ID);
        final String tokenPipelineId = JwtsHelper.getStringClaim(claimsSet, CLAIM_PIPELINE_ID);
        final String context = JwtsHelper.getStringClaim(claimsSet, CLAIM_CONTEXT);
        final String sequenceId = getFieldFromContext(context, CONTEXT_SEQUENCE_ID);

        // we need to validate the format for our instance id
        // <organization-id>:<project-id>:<pipeline-id>:<sequence-id>

        final String claimsInstanceId = tokenOrganizationId + ":" + tokenProjectId + ":"
                + tokenPipelineId + ":" + sequenceId;
        if (!claimsInstanceId.equals(instanceId)) {
            errMsg.append("instance id: ").append(instanceId).append(" does not match claims instance id: ").append(claimsInstanceId);
            return false;
        }

        return true;
    }

    String getFieldFromContext(final String context, final String field) {
        if (StringUtil.isEmpty(context)) {
            return null;
        }
        final String fieldPrefix = field + ":";
        String[] parts = context.split("/");
        for (String part : parts) {
            if (part.startsWith(fieldPrefix)) {
                return part.substring(fieldPrefix.length());
            }
        }
        return null;
    }

    boolean validateSubject(JWTClaimsSet claimsSet, final String subject, StringBuilder errMsg) {

        // extract the account, organization, project and pipeline ids from the subject

        final String tokenAccountId = JwtsHelper.getStringClaim(claimsSet, CLAIM_ACCOUNT_ID);
        final String tokenOrganizationId = JwtsHelper.getStringClaim(claimsSet, CLAIM_ORGANIZATION_ID);
        final String tokenProjectId = JwtsHelper.getStringClaim(claimsSet, CLAIM_PROJECT_ID);
        final String tokenPipelineId = JwtsHelper.getStringClaim(claimsSet, CLAIM_PIPELINE_ID);

        // we need to verify that the subject is in the correct format
        // account/<account-id>:org/<organization-id>:project/<project-id>[:pipeline/<pipeline-id>]

        String claimsSubject = "account/" + tokenAccountId + ":org/" + tokenOrganizationId + ":project/" + tokenProjectId;
        if (!claimsSubject.equals(subject)) {
            claimsSubject += ":pipeline/" + tokenPipelineId;
            if (!claimsSubject.equals(subject)) {
                errMsg.append("subject: ").append(subject).append(" does not match subject fields: ").append(claimsSubject);
                return false;
            }
        }

        return true;
    }

    boolean validateTenantDomainToken(final JWTClaimsSet claimsSet, final String domainName, final String serviceName,
            StringBuilder errMsg) {

        final String context = JwtsHelper.getStringClaim(claimsSet, CLAIM_CONTEXT);
        final String triggerType = getFieldFromContext(context, CONTEXT_TRIGGER_TYPE);
        final String triggerEvent = getFieldFromContext(context, CONTEXT_TRIGGER_EVENT);
        if (StringUtil.isEmpty(triggerType)) {
            errMsg.append("token does not contain required trigger type: ").append(context);
            return false;
        }

        // we need to generate our resource value based on the subject

        final String subject = claimsSet.getSubject();
        if (StringUtil.isEmpty(subject)) {
            errMsg.append("token does not contain required subject claim");
            return false;
        }

        // validate our subject with claims included

        if (!validateSubject(claimsSet, subject, errMsg)) {
            return false;
        }

        // generate our principal object and carry out authorization check

        final String resource = domainName + ":" + subject;
        String action = "harness." + triggerType;
        if (!StringUtil.isEmpty(triggerEvent) && !CONTEXT_TRIGGER_ID_NULL.equals(triggerEvent)) {
            action += "." + triggerEvent;
        }

        Principal principal = SimplePrincipal.create(domainName, serviceName, (String) null);
        boolean accessCheck = authorizer.access(action, resource, principal, null);
        if (!accessCheck) {
            errMsg.append("authorization check failed for action: ").append(action.toLowerCase())
                    .append(" resource: ").append(resource.toLowerCase());
        }
        return accessCheck;
    }
}
