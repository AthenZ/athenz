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

import javax.net.ssl.SSLContext;
import java.util.*;
import java.util.concurrent.TimeUnit;

import static com.yahoo.athenz.common.server.util.config.ConfigManagerSingleton.CONFIG_MANAGER;

public class InstanceGithubActionsProviderCommon implements InstanceProvider {
    protected static Logger LOGGER;

    private static final String URI_INSTANCE_ID_PREFIX = "athenz://instanceid/";
    private static final String URI_SPIFFE_PREFIX      = "spiffe://";

    protected static String GITHUB_ACTIONS_PROP_PROVIDER_DNS_SUFFIX;
    protected static String GITHUB_ACTIONS_PROP_BOOT_TIME_OFFSET;
    protected static String GITHUB_ACTIONS_PROP_CERT_EXPIRY_TIME;
    protected static String GITHUB_ACTIONS_PROP_ENTERPRISE;
    protected static String GITHUB_ACTIONS_PROP_AUDIENCE;
    protected static String GITHUB_ACTIONS_PROP_ISSUER;
    protected static String GITHUB_ACTIONS_PROP_JWKS_URI;

    static final String GITHUB_ACTIONS_ISSUER          = "https://token.actions.githubusercontent.com";
    static final String GITHUB_ACTIONS_ISSUER_JWKS_URI = "https://token.actions.githubusercontent.com/.well-known/jwks";

    public static final String CLAIM_ENTERPRISE    = "enterprise";
    public static final String CLAIM_RUN_ID        = "run_id";
    public static final String CLAIM_EVENT_NAME    = "event_name";
    public static final String CLAIM_REPOSITORY    = "repository";

    Set<String> dnsSuffixes = null;
    String githubIssuer = null;
    String provider = null;
    String audience = null;
    String enterprise = null;
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

        this.provider = provider;
        audience = System.getProperty(GITHUB_ACTIONS_PROP_AUDIENCE, "athenz.io");

        final String dnsSuffix = System.getProperty(GITHUB_ACTIONS_PROP_PROVIDER_DNS_SUFFIX, "github-actions.athenz.io");
        dnsSuffixes = new HashSet<>();
        dnsSuffixes.addAll(Arrays.asList(dnsSuffix.split(",")));

        long timeout = TimeUnit.SECONDS.convert(5, TimeUnit.MINUTES);
        bootTimeOffsetSeconds = new DynamicConfigLong(CONFIG_MANAGER, GITHUB_ACTIONS_PROP_BOOT_TIME_OFFSET, timeout);

        enterprise = System.getProperty(GITHUB_ACTIONS_PROP_ENTERPRISE);

        certExpiryTime = Long.parseLong(System.getProperty(GITHUB_ACTIONS_PROP_CERT_EXPIRY_TIME, "360"));

        githubIssuer = System.getProperty(GITHUB_ACTIONS_PROP_ISSUER, GITHUB_ACTIONS_ISSUER);
        jwtProcessor = JwtsHelper.getJWTProcessor(new JwtsSigningKeyResolver(extractGitHubIssuerJwksUri(githubIssuer), null));
    }

    String extractGitHubIssuerJwksUri(final String issuer) {
        String jwksUri = System.getProperty(GITHUB_ACTIONS_PROP_JWKS_URI);
        if (!StringUtil.isEmpty(jwksUri)) {
            return jwksUri;
        }

        final String openIdConfigUri = issuer + "/.well-known/openid-configuration";
        JwtsHelper helper = new JwtsHelper();
        jwksUri = helper.extractJwksUri(openIdConfigUri, null);

        return StringUtil.isEmpty(jwksUri) ? GITHUB_ACTIONS_ISSUER_JWKS_URI : jwksUri;
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
        if (authorizer == null) {
            throw forbiddenError("Authorizer not available");
        }

        final String instanceDomain = confirmation.getDomain();
        final String instanceService = confirmation.getService();
        final Map<String, String> instanceAttributes = confirmation.getAttributes();

        if (!StringUtil.isEmpty(InstanceUtils.getInstanceProperty(instanceAttributes,
                InstanceProvider.ZTS_INSTANCE_SAN_IP))) {
            throw forbiddenError("Request must not have any sanIP addresses");
        }

        if (!StringUtil.isEmpty(InstanceUtils.getInstanceProperty(instanceAttributes,
                InstanceProvider.ZTS_INSTANCE_HOSTNAME))) {
            throw forbiddenError("Request must not have any hostname values");
        }

        if (!validateSanUri(InstanceUtils.getInstanceProperty(instanceAttributes,
                InstanceProvider.ZTS_INSTANCE_SAN_URI))) {
            throw forbiddenError("Unable to validate certificate request URI values");
        }

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

        StringBuilder instanceId = new StringBuilder(256);
        if (!InstanceUtils.validateCertRequestSanDnsNames(instanceAttributes, instanceDomain,
                instanceService, dnsSuffixes, null, null, false, instanceId, null)) {
            throw forbiddenError("Unable to validate certificate request sanDNS entries");
        }

        Map<String, String> attributes = new HashMap<>();
        attributes.put(InstanceProvider.ZTS_CERT_REFRESH, "false");
        attributes.put(InstanceProvider.ZTS_CERT_USAGE, ZTS_CERT_USAGE_CLIENT);
        attributes.put(InstanceProvider.ZTS_CERT_EXPIRY_TIME, Long.toString(certExpiryTime));

        confirmation.setAttributes(attributes);
        return confirmation;
    }

    @Override
    public InstanceConfirmation refreshInstance(InstanceConfirmation confirmation) throws ProviderResourceException {
        throw forbiddenError("GitHub Action X.509 Certificates cannot be refreshed");
    }

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

        if (!githubIssuer.equals(claimsSet.getIssuer())) {
            errMsg.append("token issuer is not GitHub Actions: ").append(claimsSet.getIssuer());
            return false;
        }

        if (!audience.equals(JwtsHelper.getAudience(claimsSet))) {
            errMsg.append("token audience is not ZTS Server audience: ").append(JwtsHelper.getAudience(claimsSet));
            return false;
        }

        if (!StringUtil.isEmpty(enterprise)) {
            final String tokenEnterprise = JwtsHelper.getStringClaim(claimsSet, CLAIM_ENTERPRISE);
            if (!enterprise.equals(tokenEnterprise)) {
                errMsg.append("token enterprise is not the configured enterprise: ").append(tokenEnterprise);
                return false;
            }
        }

        Date issueDate = claimsSet.getIssueTime();
        if (issueDate == null || issueDate.getTime() < System.currentTimeMillis() -
                TimeUnit.SECONDS.toMillis(bootTimeOffsetSeconds.get())) {
            errMsg.append("job start time is not recent enough, issued at: ").append(issueDate);
            return false;
        }

        if (!validateInstanceId(instanceId, claimsSet, errMsg)) {
            return false;
        }

        return validateTenantDomainToken(claimsSet, domainName, serviceName, errMsg);
    }

    boolean validateInstanceId(final String instanceId, JWTClaimsSet claimsSet, StringBuilder errMsg) {
        final String runId = JwtsHelper.getStringClaim(claimsSet, CLAIM_RUN_ID);
        final String repository = JwtsHelper.getStringClaim(claimsSet, CLAIM_REPOSITORY);
        if (StringUtil.isEmpty(runId) || StringUtil.isEmpty(repository)) {
            errMsg.append("token does not contain required run_id or repository claims");
            return false;
        }
        final String tokenInstanceId = repository.replace("/", ":") + ":" + runId;
        if (!tokenInstanceId.equals(instanceId)) {
            errMsg.append("invalid instance id: ").append(tokenInstanceId).append("/").append(instanceId);
            return false;
        }
        return true;
    }

    boolean validateTenantDomainToken(final JWTClaimsSet claimsSet, final String domainName, final String serviceName,
            StringBuilder errMsg) {

        final String eventName = JwtsHelper.getStringClaim(claimsSet, CLAIM_EVENT_NAME);
        if (StringUtil.isEmpty(eventName)) {
            errMsg.append("token does not contain required event_name claim");
            return false;
        }
        final String action = "github." + eventName;

        final String subject = claimsSet.getSubject();
        if (StringUtil.isEmpty(subject)) {
            errMsg.append("token does not contain required subject claim");
            return false;
        }

        final String resource = domainName + ":" + subject;
        Principal principal = SimplePrincipal.create(domainName, serviceName, (String) null);
        boolean accessCheck = authorizer.access(action, resource, principal, null);
        if (!accessCheck) {
            errMsg.append("authorization check failed for action: ").append(action)
                    .append(" resource: ").append(resource);
        }
        return accessCheck;
    }
}
