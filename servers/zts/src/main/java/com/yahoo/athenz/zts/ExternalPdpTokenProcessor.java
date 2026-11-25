/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.zts;

import com.nimbusds.jwt.JWTClaimsSet;
import com.nimbusds.jwt.SignedJWT;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.PrivateKeyStore;
import com.yahoo.athenz.auth.ServerPrivateKey;
import com.yahoo.athenz.auth.TokenExchangeIdentityProvider;
import com.yahoo.athenz.auth.token.AccessToken;
import com.yahoo.athenz.auth.token.IdToken;
import com.yahoo.athenz.auth.token.OAuth2Token;
import com.yahoo.athenz.auth.util.AthenzUtils;
import com.yahoo.athenz.common.server.pdp.ExternalPdpContext;
import com.yahoo.athenz.common.server.pdp.ExternalPdpException;
import com.yahoo.athenz.common.server.pdp.ExternalPolicyDecisionPoint;
import com.yahoo.athenz.common.server.pdp.authzen.EvaluationsResponse;
import com.yahoo.athenz.common.server.pdp.authzen.Subject;
import com.yahoo.athenz.common.server.util.ResourceUtils;
import com.yahoo.athenz.common.server.util.ServletRequestUtil;
import com.yahoo.athenz.zts.cache.DataCache;
import com.yahoo.athenz.zts.store.DataStore;
import com.yahoo.athenz.zts.token.IssuerResolver;
import com.yahoo.athenz.zts.token.ProviderConfigManager;
import com.yahoo.athenz.zts.token.TokenIssuanceConfig;
import com.yahoo.athenz.zts.token.TokenIssuanceErrors;
import com.yahoo.athenz.zts.token.TokenIssuancePolicy;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.server.spiffe.SpiffeUriManager;
import com.yahoo.rdl.Validator;
import com.yahoo.athenz.zts.pdp.AdditionalClaimsValidator;
import com.yahoo.athenz.zts.pdp.AuthZenRequestBuilder;
import com.yahoo.athenz.zts.pdp.ExternalPdpConfig;
import com.yahoo.athenz.zts.pdp.ExternalPdpDecision;
import com.yahoo.athenz.zts.pdp.ExternalPdpDecisionLog;
import com.yahoo.athenz.zts.pdp.ExternalPdpEvaluation;
import com.yahoo.athenz.zts.pdp.ExternalPdpFlow;
import com.yahoo.athenz.zts.pdp.ExternalPdpManager;
import com.yahoo.athenz.zts.pdp.ExternalPdpMode;
import com.yahoo.athenz.zts.token.AccessTokenRequest;
import com.yahoo.athenz.zts.token.AccessTokenRequest.RequestType;
import com.yahoo.athenz.zts.token.AccessTokenScope;
import com.yahoo.athenz.zts.utils.ZTSUtils;
import com.yahoo.athenz.zms.Role;
import org.eclipse.jetty.util.StringUtil;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.Closeable;
import java.time.Instant;
import java.util.*;
import java.util.concurrent.TimeUnit;

/**
 * Routes OAuth2 token requests through the external PDP. The PDP-path flows
 * mirror the legacy ZTSImpl flows and must be kept in sync with them:
 * processStandard - processAccessTokenStandardRequest,
 * processImpersonation - processAccessTokenImpersonationRequest,
 * processDelegation - processAccessTokenDelegationRequest,
 * processJAGIssue - processJAGTokenIssueRequest,
 * processJAGExchange - processJAGTokenExchangeRequest.
 */
public class ExternalPdpTokenProcessor implements Closeable {

    private static final Logger LOGGER = LoggerFactory.getLogger(ExternalPdpTokenProcessor.class);

    static final String TYPE_DOMAIN_NAME = "DomainName";
    static final String TYPE_ENTITY_NAME = "EntityName";
    static final String TYPE_SERVICE_NAME = "ServiceName";
    static final String TYPE_SIMPLE_NAME = "SimpleName";

    static final String OAUTH_NA_TOKEN = "N_A";
    static final String OAUTH_JAG_TOKEN = "urn:ietf:params:oauth:token-type:id-jag";
    static final String ACCESS_LOG_ADDL_QUERY = "com.yahoo.athenz.uri.addl_query";

    static final String KEY_SUBJECT = "subject";
    static final String KEY_CLIENT = "client";
    static final String KEY_SOURCE_EXCHANGE = "source_exchange";
    static final String KEY_TARGET_EXCHANGE = "target_exchange";

    static final String METRIC_EVAL = "zts_ext_pdp_eval";
    static final String METRIC_EVAL_LATENCY = "zts_ext_pdp_eval_latency";
    static final String METRIC_AUDIT_DIFF = "zts_ext_pdp_audit_diff";
    static final String METRIC_CLAIMS_REJECTED = "zts_ext_pdp_claims_rejected";
    static final String METRIC_ROLE_CREDENTIAL_REQUEST = "zts_ext_pdp_role_credential_request";
    static final String METRIC_ROLE_CREDENTIAL_REJECTED = "zts_ext_pdp_role_credential_rejected";

    static final String OUTCOME_PERMIT = "permit";
    static final String OUTCOME_PARTIAL = "partial";
    static final String OUTCOME_DENY = "deny";
    static final String OUTCOME_ERROR = "error";
    static final String OUTCOME_TIMEOUT = "timeout";
    static final String OUTCOME_REJECTED = "rejected";
    static final String OUTCOME_AUDIT_DROPPED = "audit_dropped";

    static final String EXCHANGE_IMPERSONATION = "impersonation";
    static final String EXCHANGE_DELEGATION = "delegation";

    private final ExternalPdpConfig config;
    private final ExternalPdpManager manager;
    private final ExternalPdpMode mode;
    private final AuthZenRequestBuilder builder;
    private final AdditionalClaimsValidator claimsValidator;
    private final Services services;
    private final TokenIssuanceConfig tokenConfig;
    private final TokenIssuanceErrors errors = new ProcessorErrors();

    /**
     * Legacy (RBAC only) token issuance used by AUDIT mode to issue the token.
     */
    @FunctionalInterface
    interface LegacyTokenFlow {
        AccessTokenResponse process(ResourceContext ctx, Principal principal, AccessTokenRequest accessTokenRequest,
                String principalDomain, String caller);
    }

    /**
     * Server facilities used by the PDP-path token flows. All values are
     * fixed after server startup.
     */
    static final class Services {
        final PrivateKeyStore privateKeyStore;
        final DataStore dataStore;
        final ZTSAuthorizer authorizer;
        final IssuerResolver issuerResolver;
        final ProviderConfigManager providerConfigManager;
        final Metric metric;
        final Validator validator;
        final String userDomain;
        final SpiffeUriManager spiffeUriManager;
        final TokenIssuanceConfig tokenIssuanceConfig;
        final String keyAlgoForJsonWebObjects;
        final ServerPrivateKey privateRSAKey;
        final ServerPrivateKey privateECKey;
        final ServerPrivateKey privateOrigKey;
        final LegacyTokenFlow legacyFlow;

        private Services(final Builder builder) {
            privateKeyStore = builder.privateKeyStore;
            dataStore = builder.dataStore;
            authorizer = builder.authorizer;
            issuerResolver = builder.issuerResolver;
            providerConfigManager = builder.providerConfigManager;
            metric = builder.metric;
            validator = builder.validator;
            userDomain = builder.userDomain;
            spiffeUriManager = builder.spiffeUriManager;
            tokenIssuanceConfig = builder.tokenIssuanceConfig;
            keyAlgoForJsonWebObjects = builder.keyAlgoForJsonWebObjects;
            privateRSAKey = builder.privateRSAKey;
            privateECKey = builder.privateECKey;
            privateOrigKey = builder.privateOrigKey;
            legacyFlow = builder.legacyFlow;
        }

        static final class Builder {
            private PrivateKeyStore privateKeyStore;
            private DataStore dataStore;
            private ZTSAuthorizer authorizer;
            private IssuerResolver issuerResolver;
            private ProviderConfigManager providerConfigManager;
            private Metric metric;
            private Validator validator;
            private String userDomain;
            private SpiffeUriManager spiffeUriManager;
            private TokenIssuanceConfig tokenIssuanceConfig;
            private String keyAlgoForJsonWebObjects;
            private ServerPrivateKey privateRSAKey;
            private ServerPrivateKey privateECKey;
            private ServerPrivateKey privateOrigKey;
            private LegacyTokenFlow legacyFlow;

            Builder privateKeyStore(final PrivateKeyStore value) {
                privateKeyStore = value;
                return this;
            }

            Builder dataStore(final DataStore value) {
                dataStore = value;
                return this;
            }

            Builder authorizer(final ZTSAuthorizer value) {
                authorizer = value;
                return this;
            }

            Builder issuerResolver(final IssuerResolver value) {
                issuerResolver = value;
                return this;
            }

            Builder providerConfigManager(final ProviderConfigManager value) {
                providerConfigManager = value;
                return this;
            }

            Builder metric(final Metric value) {
                metric = value;
                return this;
            }

            Builder validator(final Validator value) {
                validator = value;
                return this;
            }

            Builder userDomain(final String value) {
                userDomain = value;
                return this;
            }

            Builder spiffeUriManager(final SpiffeUriManager value) {
                spiffeUriManager = value;
                return this;
            }

            Builder tokenIssuanceConfig(final TokenIssuanceConfig value) {
                tokenIssuanceConfig = value;
                return this;
            }

            Builder signingKeys(final String keyAlgo, final ServerPrivateKey rsaKey, final ServerPrivateKey ecKey,
                    final ServerPrivateKey origKey) {
                keyAlgoForJsonWebObjects = keyAlgo;
                privateRSAKey = rsaKey;
                privateECKey = ecKey;
                privateOrigKey = origKey;
                return this;
            }

            Builder legacyFlow(final LegacyTokenFlow value) {
                legacyFlow = value;
                return this;
            }

            Services build() {
                return new Services(this);
            }
        }
    }

    ExternalPdpTokenProcessor(final ExternalPdpConfig config, final ExternalPdpManager manager,
            final Services services) {
        this.config = config;
        this.manager = manager;
        this.mode = config.getMode();
        this.services = services;
        this.tokenConfig = services.tokenIssuanceConfig;
        this.builder = new AuthZenRequestBuilder(services.userDomain);
        this.claimsValidator = new AdditionalClaimsValidator(config);
    }

    /**
     * Create the processor based on the server configuration.
     * @param services server facilities used by the token flows
     * @return processor or null if the external pdp is disabled
     */
    static ExternalPdpTokenProcessor create(final Services services) {
        if (ExternalPdpConfig.modeFromSystemProperties() == ExternalPdpMode.DISABLED) {
            return null;
        }
        final ExternalPdpConfig config = ExternalPdpConfig.fromSystemProperties();
        final ExternalPolicyDecisionPoint pdp = ExternalPdpManager.loadPdp(config.getEndpoint());
        final ExternalPdpContext.Builder contextBuilder = new ExternalPdpContext.Builder()
                .sslContext(ZTSUtils.getAthenzProviderClientSSLContext(services.privateKeyStore))
                .rolesProvider(services.dataStore)
                .privateKeyStore(services.privateKeyStore);
        try {
            return new ExternalPdpTokenProcessor(config, new ExternalPdpManager(config, pdp, contextBuilder), services);
        } catch (ExternalPdpException ex) {
            throw new IllegalArgumentException("Unable to initialize external pdp: " + ex.getMessage(), ex);
        }
    }

    // errors are logged and metered the same way as the legacy token flows

    RuntimeException error(int code, final String msg, final String caller, final String requestDomain,
            final String principalDomain) {
        LOGGER.error("Error: {} request-domain: {} principal-domain: {} code: {} message: {}",
                caller, requestDomain, principalDomain, code, msg);
        ZTSUtils.emitMonmetricError(code, caller, requestDomain, principalDomain, services.metric);
        return new ResourceException(code, new ResourceError().code(code).message(msg));
    }

    RuntimeException requestError(final String msg, final String caller, final String requestDomain,
            final String principalDomain) {
        return error(ResourceException.BAD_REQUEST, msg, caller, requestDomain, principalDomain);
    }

    RuntimeException forbiddenError(final String msg, final String caller, final String requestDomain,
            final String principalDomain) {
        return error(ResourceException.FORBIDDEN, msg, caller, requestDomain, principalDomain);
    }

    RuntimeException notFoundError(final String msg, final String caller, final String requestDomain,
            final String principalDomain) {
        return error(ResourceException.NOT_FOUND, msg, caller, requestDomain, principalDomain);
    }

    final class ProcessorErrors implements TokenIssuanceErrors {
        @Override
        public RuntimeException requestError(final String msg, final String caller, final String requestDomain,
                final String principalDomain) {
            return ExternalPdpTokenProcessor.this.requestError(msg, caller, requestDomain, principalDomain);
        }

        @Override
        public RuntimeException forbiddenError(final String msg, final String caller, final String requestDomain,
                final String principalDomain) {
            return ExternalPdpTokenProcessor.this.forbiddenError(msg, caller, requestDomain, principalDomain);
        }
    }

    // token issuance rules shared with the legacy flows

    void validate(final Object val, final String type, final String principalDomain, final String caller) {
        TokenIssuancePolicy.validate(services.validator, val, type, principalDomain, caller, errors);
    }

    static void setRequestDomain(final ResourceContext ctx, final String requestDomainName) {
        ((RsrcCtxWrapper) ctx).setRequestDomain(requestDomainName);
    }

    static String getRequestDomainName(final ResourceContext ctx) {
        return ((RsrcCtxWrapper) ctx).getRequestDomain();
    }

    int determineTokenTimeout(final DataCache data, final Set<String> roles, final Integer minExpiryTime,
            final Integer maxExpiryTime) {
        return TokenIssuancePolicy.determineTokenTimeout(data, roles, minExpiryTime, maxExpiryTime,
                tokenConfig.getRoleTokenDefaultTimeout(), tokenConfig.getRoleTokenMaxTimeout());
    }

    int determineTokenExchangeTimeout(final DataCache data, final Set<String> roles,
            final AccessTokenRequest accessTokenRequest, long issueTime, final String principalDomain,
            final String caller) {
        return TokenIssuancePolicy.determineTokenExchangeTimeout(
                determineTokenTimeout(data, roles, null, accessTokenRequest.getExpiryTime()),
                accessTokenRequest, issueTime, principalDomain, caller, errors);
    }

    ServerPrivateKey getSignPrivateKey(final String keyType) {
        return TokenIssuancePolicy.getSignPrivateKey(keyType, services.keyAlgoForJsonWebObjects,
                services.privateRSAKey, services.privateECKey, services.privateOrigKey);
    }

    /**
     * @param requestType token request type
     * @return true if requests of the given type are routed through this processor
     */
    boolean handles(final RequestType requestType) {
        final ExternalPdpFlow flow = ExternalPdpFlow.fromRequestType(requestType);
        return flow != null && config.getFlows().contains(flow);
    }

    ExternalPdpMode getMode() {
        return mode;
    }

    /**
     * Reject role certificate and role token requests while the PDP is
     * enforcing. In AUDIT mode the request is served and recorded.
     * @param ctx request context
     * @param caller api name
     * @param principalDomain principal domain name
     */
    void checkRoleCredentialRequest(final ResourceContext ctx, final String caller, final String principalDomain) {
        final Principal principal = ((RsrcCtxWrapper) ctx).principal();
        final String principalName = principal == null ? null : principal.getFullName();
        if (mode == ExternalPdpMode.AUDIT) {
            services.metric.increment(METRIC_ROLE_CREDENTIAL_REQUEST, "api", caller);
            new ExternalPdpDecisionLog(UUID.randomUUID().toString(), mode, "role_credential")
                    .with("api", caller).with("principal", principalName).write();
            return;
        }
        services.metric.increment(METRIC_ROLE_CREDENTIAL_REJECTED, "api", caller);
        throw forbiddenError(caller + ": role credentials are not supported when external PDP is enabled",
                caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
    }

    /**
     * Process an access token request through the external PDP.
     * @param ctx request context
     * @param principal authenticated principal
     * @param accessTokenRequest parsed token request
     * @param principalDomain principal domain name
     * @param caller api name
     * @return token response
     */
    AccessTokenResponse process(final ResourceContext ctx, final Principal principal,
            final AccessTokenRequest accessTokenRequest, final String principalDomain, final String caller) {

        if (mode == ExternalPdpMode.AUDIT) {
            return processAudit(ctx, principal, accessTokenRequest, principalDomain, caller);
        }

        final PdpRequest pr = new PdpRequest(flowName(accessTokenRequest), manager.newDeadline());
        try {
            AccessTokenResponse response = processFlow(ctx, principal, accessTokenRequest, principalDomain,
                    caller, pr);
            pr.outcome = pr.isPartial() ? OUTCOME_PARTIAL : OUTCOME_PERMIT;
            return response;
        } catch (RuntimeException ex) {
            pr.outcome = outcomeForException(ex, pr);
            throw ex;
        } finally {
            finish(ctx, principal, pr);
        }
    }

    AccessTokenResponse processFlow(final ResourceContext ctx, final Principal principal,
            final AccessTokenRequest accessTokenRequest, final String principalDomain, final String caller,
            final PdpRequest pr) {
        switch (accessTokenRequest.getRequestType()) {
            case ACCESS_TOKEN_EXCHANGE:
                TokenIssuancePolicy.disallowAuthorizedServicePrincipal(principal.getAuthorizedService(), "token exchange",
                        caller, principalDomain, errors);
                if (accessTokenRequest.getActorTokenObj() != null) {
                    return processDelegation(ctx, principal, accessTokenRequest, principalDomain, caller, pr);
                }
                return processImpersonation(ctx, principal, accessTokenRequest, principalDomain, caller, pr);
            case JAG_TOKEN_EXCHANGE:
                return processJAGIssue(ctx, principal, accessTokenRequest, principalDomain, caller, pr);
            case JAG_JWT_BEARER:
                return processJAGExchange(ctx, principal, accessTokenRequest, principalDomain, caller, pr);
            default:
                return processStandard(ctx, principal, accessTokenRequest, principalDomain, caller, pr);
        }
    }

    static String flowName(final AccessTokenRequest accessTokenRequest) {
        switch (accessTokenRequest.getRequestType()) {
            case ACCESS_TOKEN_EXCHANGE:
                return accessTokenRequest.getActorTokenObj() != null ? EXCHANGE_DELEGATION : EXCHANGE_IMPERSONATION;
            case JAG_TOKEN_EXCHANGE:
                return "jag_issue";
            case JAG_JWT_BEARER:
                return "jag_exchange";
            default:
                return "access_token";
        }
    }

    static String outcomeForException(final RuntimeException ex, final PdpRequest pr) {
        if (!(ex instanceof ResourceException)) {
            return OUTCOME_ERROR;
        }
        switch (((ResourceException) ex).getCode()) {
            case ResourceException.FORBIDDEN:
                return OUTCOME_DENY;
            case ResourceException.SERVICE_UNAVAILABLE:
                return pr.errorCode == ExternalPdpException.Code.TIMEOUT ? OUTCOME_TIMEOUT : OUTCOME_ERROR;
            default:
                return OUTCOME_REJECTED;
        }
    }

    /**
     * Per-request state used for decision logging and metrics.
     */
    static final class PdpRequest {
        final String requestId = UUID.randomUUID().toString();
        final String flow;
        final long deadline;
        final long startNanos = System.nanoTime();
        ExternalPdpEvaluation evaluation;
        ExternalPdpDecision decision;
        Map<String, Set<String>> finalRoles;
        List<String> claimNames;
        List<String> claimsRejected;
        final List<String> undefinedRoles = new ArrayList<>();
        ExternalPdpException.Code errorCode;
        String outcome;

        PdpRequest(final String flow, long deadline) {
            this.flow = flow;
            this.deadline = deadline;
        }

        int candidateCount() {
            return evaluation == null ? 0 : countRoles(evaluation.getCandidates().get(KEY_SUBJECT));
        }

        int finalCount() {
            return countRoles(finalRoles);
        }

        boolean isPartial() {
            return finalCount() < candidateCount();
        }

        static int countRoles(final Map<String, Set<String>> rolesByDomain) {
            if (rolesByDomain == null) {
                return 0;
            }
            int count = 0;
            for (Set<String> roles : rolesByDomain.values()) {
                count += roles.size();
            }
            return count;
        }
    }

    void finish(final ResourceContext ctx, final Principal principal, final PdpRequest pr) {

        services.metric.increment(METRIC_EVAL, "mode", mode.name(), "flow", pr.flow, "outcome", pr.outcome);

        ExternalPdpDecisionLog log = new ExternalPdpDecisionLog(pr.requestId, mode, pr.flow)
                .with("outcome", pr.outcome)
                .with("principal", principal.getFullName())
                .with("audience", getRequestDomainName(ctx))
                .with("candidate_roles", pr.evaluation == null ? null : pr.evaluation.getCandidates())
                .with("final_roles", pr.finalRoles)
                .with("claim_names", pr.claimNames)
                .with("claims_rejected", pr.claimsRejected)
                .with("undefined_roles", pr.undefinedRoles.isEmpty() ? null : pr.undefinedRoles)
                .with("error_code", pr.errorCode)
                .with("latency_ms", TimeUnit.NANOSECONDS.toMillis(System.nanoTime() - pr.startNanos));
        if (pr.decision != null) {
            log.with("gate", pr.decision.isGatePermitted())
                    .with("permitted_roles", pr.decision.getPermittedRoles())
                    .with("max_expires_in", pr.decision.getMaxExpiresIn())
                    .with("fail_open", pr.decision.isFailOpen() ? Boolean.TRUE : null)
                    .with("reasons", pr.decision.getReasons().isEmpty() ? null : pr.decision.getReasons());
        }
        log.write();

        final Object current = ctx.request().getAttribute(ACCESS_LOG_ADDL_QUERY);
        StringBuilder query = new StringBuilder(current == null ? "" : current.toString());
        if (query.length() > 0) {
            query.append('&');
        }
        query.append("pdp_mode=").append(mode.name().toLowerCase(Locale.ROOT))
                .append("&pdp_request_id=").append(pr.requestId)
                .append("&pdp_removed=").append(Math.max(0, pr.candidateCount() - pr.finalCount()));
        ctx.request().setAttribute(ACCESS_LOG_ADDL_QUERY, query.toString());
    }

    Map<String, Object> requestContext(final ResourceContext ctx, final Principal principal,
            final AccessTokenRequest accessTokenRequest, final String requestId, final String audience,
            final String exchangeType, final ExternalPdpMode contextMode) {
        Map<String, Object> context = new LinkedHashMap<>();
        context.put(AuthZenRequestBuilder.CTX_REQUEST_ID, requestId);
        context.put(AuthZenRequestBuilder.CTX_TIME, Instant.now().toString());
        putIfNotEmpty(context, AuthZenRequestBuilder.CTX_GRANT_TYPE, accessTokenRequest.getGrantType());
        context.put(AuthZenRequestBuilder.CTX_REQUEST_TYPE, accessTokenRequest.getRequestType().name());
        putIfNotEmpty(context, AuthZenRequestBuilder.CTX_EXCHANGE_TYPE, exchangeType);
        putIfNotEmpty(context, AuthZenRequestBuilder.CTX_CLIENT_IP, ServletRequestUtil.getRemoteAddress(ctx.request()));
        putIfNotEmpty(context, AuthZenRequestBuilder.CTX_AUDIENCE, audience);
        putIfNotEmpty(context, AuthZenRequestBuilder.CTX_REQUESTED_SCOPE, accessTokenRequest.getScope());
        if (accessTokenRequest.getExpiryTime() > 0) {
            context.put(AuthZenRequestBuilder.CTX_REQUESTED_EXPIRES_IN, accessTokenRequest.getExpiryTime());
        }
        putIfNotEmpty(context, AuthZenRequestBuilder.CTX_PROXY_FOR_PRINCIPAL, accessTokenRequest.getProxyForPrincipal());
        putIfNotEmpty(context, AuthZenRequestBuilder.CTX_ACTOR, accessTokenRequest.getActor());
        context.put(AuthZenRequestBuilder.CTX_CLIENT, principal.getFullName());
        final OAuth2Token subjectToken = accessTokenRequest.getRequestType() == RequestType.JAG_JWT_BEARER
                ? accessTokenRequest.getJagTokenObj() : accessTokenRequest.getSubjectTokenObj();
        if (subjectToken != null) {
            context.put(AuthZenRequestBuilder.CTX_SUBJECT_TOKEN, AuthZenRequestBuilder.tokenClaims(subjectToken));
        }
        if (accessTokenRequest.getActorTokenObj() != null) {
            context.put(AuthZenRequestBuilder.CTX_ACTOR_TOKEN,
                    AuthZenRequestBuilder.tokenClaims(accessTokenRequest.getActorTokenObj()));
        }
        context.put(AuthZenRequestBuilder.CTX_DPOP_BOUND, accessTokenRequest.getDPoPJwkThumbprint() != null);
        context.put(AuthZenRequestBuilder.CTX_MODE, contextMode.name());
        return context;
    }

    static void putIfNotEmpty(final Map<String, Object> map, final String key, final String value) {
        if (!StringUtil.isEmpty(value)) {
            map.put(key, value);
        }
    }

    ExternalPdpDecision decide(final ExternalPdpEvaluation evaluation, final PdpRequest pr, final String caller,
            final String domainName, final String principalDomain) {
        pr.evaluation = evaluation;
        final Object timer = services.metric.startTiming(METRIC_EVAL_LATENCY, domainName, principalDomain);
        try {
            EvaluationsResponse response = manager.evaluations(evaluation.toRequest(), pr.deadline);
            pr.decision = evaluation.decide(response);
        } catch (ExternalPdpException ex) {
            pr.errorCode = ex.getCode();
            LOGGER.error("External PDP evaluation failed: request-id: {} code: {} message: {}",
                    pr.requestId, ex.getCode(), ex.getMessage());
            if (mode != ExternalPdpMode.FILTER || !config.isFailOpen()) {
                throw pdpUnavailable(caller, domainName, principalDomain);
            }
            pr.decision = evaluation.failOpen(config.getFailOpenMaxExpiresIn());
        } finally {
            services.metric.stopTiming(timer, domainName, principalDomain);
        }
        return pr.decision;
    }

    RuntimeException pdpUnavailable(final String caller, final String domainName, final String principalDomain) {
        return error(ResourceException.SERVICE_UNAVAILABLE, "External policy decision point unavailable",
                caller, domainName, principalDomain);
    }

    static boolean isRoleDefined(final DataCache data, final String role) {
        return data.getRoleMeta(role) != null;
    }

    static int applyMaxExpiry(int tokenTimeout, final ExternalPdpDecision decision) {
        final Integer maxExpiresIn = decision.getMaxExpiresIn();
        return maxExpiresIn == null ? tokenTimeout : Math.min(tokenTimeout, maxExpiresIn);
    }

    Set<String> authoritativeRoles(final DataCache data, final String domainName, final String[] requestedRoles,
            final PdpRequest pr, final String caller, final String principalDomain) {
        Set<String> roles;
        if (requestedRoles != null) {
            roles = new TreeSet<>(Arrays.asList(requestedRoles));
        } else if (config.isRequireDefinedRoles()) {
            roles = definedRoles(data);
        } else {
            throw requestError("invalid_scope: domain scope requires explicit roles", caller,
                    domainName, principalDomain);
        }
        if (config.isRequireDefinedRoles()) {
            Iterator<String> iterator = roles.iterator();
            while (iterator.hasNext()) {
                final String role = iterator.next();
                if (!isRoleDefined(data, role)) {
                    pr.undefinedRoles.add(ResourceUtils.roleResourceName(domainName, role));
                    iterator.remove();
                }
            }
        }
        if (roles.size() > config.getMaxCandidateRoles()) {
            throw requestError("invalid_scope: too many roles for external policy evaluation", caller,
                    domainName, principalDomain);
        }
        return roles;
    }

    static Set<String> definedRoles(final DataCache data) {
        Set<String> roles = new TreeSet<>();
        final List<Role> domainRoles = data.getDomainData().getRoles();
        if (domainRoles == null) {
            return roles;
        }
        for (Role role : domainRoles) {
            final String roleName = AthenzUtils.extractRoleName(role.getName());
            if (roleName != null) {
                roles.add(roleName);
            }
        }
        return roles;
    }

    // pdp claims are applied before any server computed custom claims so the
    // server values always take precedence over a pdp claim with the same name

    void applyClaims(final AccessToken accessToken, final ExternalPdpDecision decision, final PdpRequest pr,
            final String caller, final String domainName, final String principalDomain) {

        if (!config.isClaimsEnabled() || decision.isFailOpen()) {
            return;
        }
        if (decision.isClaimsMalformed()) {
            pr.claimsRejected = Collections.singletonList("claims");
            services.metric.increment(METRIC_CLAIMS_REJECTED, "flow", pr.flow);
            if (config.isClaimsStrict()) {
                throw forbiddenError("Additional token claims rejected", caller, domainName, principalDomain);
            }
            return;
        }
        final Map<String, Object> claims = decision.getClaims();
        if (claims == null || claims.isEmpty()) {
            return;
        }
        AdditionalClaimsValidator.Result result = claimsValidator.validate(claims);
        if (!result.getRejected().isEmpty()) {
            pr.claimsRejected = result.getRejected();
            services.metric.increment(METRIC_CLAIMS_REJECTED, "flow", pr.flow);
        }
        if (result.isFailed()) {
            throw forbiddenError("Additional token claims rejected", caller, domainName, principalDomain);
        }
        List<String> names = new ArrayList<>();
        for (Map.Entry<String, Object> claim : result.getAccepted().entrySet()) {
            if (accessToken.setCustomClaim(claim.getKey(), claim.getValue())) {
                names.add(claim.getKey());
            }
        }
        pr.claimNames = names.isEmpty() ? null : names;
    }

    AccessTokenResponse processStandard(final ResourceContext ctx, final Principal principal,
            final AccessTokenRequest accessTokenRequest, final String principalDomain, final String caller,
            final PdpRequest pr) {

        String principalName = principal.getFullName();

        final String actor = accessTokenRequest.getActor();
        if (actor != null) {
            validate(actor, TYPE_SERVICE_NAME, principalDomain, caller);
        }

        TokenIssuancePolicy.validateProxyForPrincipalValue(accessTokenRequest.getProxyForPrincipal(), principalName,
                principalDomain, caller, tokenConfig.getAuthorizedProxyUsers(), services.validator, errors);

        AccessTokenScope tokenScope = new AccessTokenScope(accessTokenRequest.getScope(), principalDomain);

        Set<String> scopeDomainNames = tokenScope.getDomainNames();
        if (scopeDomainNames.size() > 1 && StringUtil.isEmpty(accessTokenRequest.getAudience())) {
            throw requestError("Multiple scope domains require an audience", caller,
                    ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }

        final String domainName = StringUtil.isEmpty(accessTokenRequest.getAudience()) ?
                tokenScope.getDomainName() : accessTokenRequest.getAudience().toLowerCase();
        setRequestDomain(ctx, domainName);
        validate(domainName, TYPE_DOMAIN_NAME, principalDomain, caller);
        if (!scopeDomainNames.contains(domainName)) {
            throw requestError("Audience domain must be one of the scope domains", caller,
                    domainName, principalDomain);
        }

        if (services.dataStore.getDataCache(domainName) == null) {
            setRequestDomain(ctx, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
            throw notFoundError("No such domain: " + domainName, caller,
                    ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }

        if (!StringUtil.isEmpty(accessTokenRequest.getAuthzDetails()) && scopeDomainNames.size() > 1) {
            throw requestError("Authorization details cannot be requested for multiple domains", caller,
                    domainName, principalDomain);
        }

        String proxyUser = null;
        final String requestPrincipalName = principalName;
        final boolean proxyForPrincipal = !StringUtil.isEmpty(accessTokenRequest.getProxyForPrincipal());
        if (proxyForPrincipal) {
            if (tokenScope.isOpenIdScope()) {
                throw requestError("Proxy Principal cannot request id tokens", caller,
                        domainName, principalDomain);
            }
            proxyUser = principalName;
            principalName = accessTokenRequest.getProxyForPrincipal();
        }

        final Subject clientSubject = builder.subject(principal);
        final Subject tokenSubject = proxyForPrincipal ? builder.subject(principalName) : clientSubject;
        final Map<String, Object> context = requestContext(ctx, principal, accessTokenRequest, pr.requestId,
                domainName, null, mode);
        ExternalPdpEvaluation evaluation = new ExternalPdpEvaluation(tokenSubject, context,
                AuthZenRequestBuilder.tokenResource(domainName, scopeDomainNames));

        Map<String, DataCache> dataByDomain = new HashMap<>();
        Map<String, String[]> requestedByDomain = new HashMap<>();
        for (String scopeDomainName : scopeDomainNames) {

            validate(scopeDomainName, TYPE_DOMAIN_NAME, principalDomain, caller);

            String[] requestedRoles = tokenScope.getRoleNames(scopeDomainName);
            if (requestedRoles != null) {
                for (String requestedRole : requestedRoles) {
                    validate(requestedRole, TYPE_ENTITY_NAME, principalDomain, caller);
                }
            }

            DataCache data = services.dataStore.getDataCache(scopeDomainName);
            if (data == null) {
                setRequestDomain(ctx, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
                throw notFoundError("No such domain: " + scopeDomainName, caller,
                        ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
            }

            TokenIssuancePolicy.validateAuthorizationDetails(accessTokenRequest.getAuthzDetails(), requestedRoles, data, caller,
                    scopeDomainName, principalDomain, tokenConfig.getMaxAuthzDetailsLength(),
                    tokenConfig.getSystemAuthzDetails(), errors);

            TokenIssuancePolicy.checkRoleTokenAuthorizedServiceRequest(principal, scopeDomainName, caller, errors);

            dataByDomain.put(scopeDomainName, data);
            requestedByDomain.put(scopeDomainName, requestedRoles);

            if (mode == ExternalPdpMode.FILTER) {
                Set<String> roles = new HashSet<>();
                services.dataStore.getAccessibleRoles(data, scopeDomainName, requestPrincipalName, requestedRoles,
                        false, roles, false);
                if (roles.isEmpty()) {
                    throw forbiddenError(TokenIssuancePolicy.tokenErrorMessage(caller, requestPrincipalName, scopeDomainName,
                            requestedRoles), caller, scopeDomainName, principalDomain);
                }
                TokenIssuancePolicy.logUnrequestedRoles(requestPrincipalName, requestedRoles, roles,
                        tokenConfig.isLogUnrequestedRolesEnabled());
                if (proxyForPrincipal) {
                    Set<String> rolesForProxy = new HashSet<>();
                    services.dataStore.getAccessibleRoles(data, scopeDomainName, accessTokenRequest.getProxyForPrincipal(),
                            requestedRoles, false, rolesForProxy, false);
                    roles.retainAll(rolesForProxy);
                    if (roles.isEmpty()) {
                        throw forbiddenError(TokenIssuancePolicy.tokenErrorMessage(caller, accessTokenRequest.getProxyForPrincipal(),
                                scopeDomainName, requestedRoles), caller, scopeDomainName, principalDomain);
                    }
                }
                for (String role : roles) {
                    evaluation.addRole(KEY_SUBJECT, scopeDomainName, role, true, Boolean.TRUE, null);
                }
            } else {
                Set<String> roles = authoritativeRoles(data, scopeDomainName, requestedRoles, pr,
                        caller, principalDomain);
                if (roles.isEmpty()) {
                    throw forbiddenError(TokenIssuancePolicy.tokenErrorMessage(caller, principalName, scopeDomainName,
                            requestedRoles), caller, scopeDomainName, principalDomain);
                }
                for (String role : roles) {
                    final boolean defined = isRoleDefined(data, role);
                    evaluation.addRole(KEY_SUBJECT, scopeDomainName, role, defined, null, null);
                    if (proxyForPrincipal) {
                        evaluation.addRole(KEY_CLIENT, scopeDomainName, role, defined, null, clientSubject);
                    }
                }
            }
        }

        ExternalPdpDecision decision = decide(evaluation, pr, caller, domainName, principalDomain);
        if (!decision.isGatePermitted()) {
            throw forbiddenError(TokenIssuancePolicy.tokenErrorMessage(caller, principalName, domainName,
                    requestedByDomain.get(domainName)), caller, domainName, principalDomain);
        }

        Map<String, Set<String>> rolesByDomain = new HashMap<>();
        int tokenTimeout = Integer.MAX_VALUE;
        boolean scopeAdjusted = false;
        for (String scopeDomainName : scopeDomainNames) {

            final String[] requestedRoles = requestedByDomain.get(scopeDomainName);
            Set<String> roles = decision.getPermittedRoles(KEY_SUBJECT, scopeDomainName);
            if (mode == ExternalPdpMode.AUTHORITATIVE && proxyForPrincipal) {
                roles.retainAll(decision.getPermittedRoles(KEY_CLIENT, scopeDomainName));
            }
            if (roles.isEmpty()) {
                throw forbiddenError(TokenIssuancePolicy.tokenErrorMessage(caller, principalName, scopeDomainName, requestedRoles),
                        caller, scopeDomainName, principalDomain);
            }

            if (!TokenIssuancePolicy.isPrincipalRoleCertificateAccessValid(principal, scopeDomainName, roles)) {
                throw forbiddenError("Role based Principal does not include all roles",
                        caller, scopeDomainName, principalDomain);
            }

            rolesByDomain.put(scopeDomainName, roles);
            int domainTokenTimeout = determineTokenTimeout(dataByDomain.get(scopeDomainName), roles, null,
                    accessTokenRequest.getExpiryTime());
            tokenTimeout = Math.min(tokenTimeout, domainTokenTimeout);
            if (tokenScope.sendScopeResponse() || requestedRoles != null && requestedRoles.length != roles.size()) {
                scopeAdjusted = true;
            }
        }
        tokenTimeout = applyMaxExpiry(tokenTimeout, decision);
        pr.finalRoles = rolesByDomain;

        long iat = System.currentTimeMillis() / 1000;
        List<String> tokenScopes = TokenIssuancePolicy.generateAccessTokenScopeList(rolesByDomain, domainName);

        AccessToken accessToken = new AccessToken();
        accessToken.setVersion(1);
        accessToken.setJwtId(UUID.randomUUID().toString());
        accessToken.setAudience(TokenIssuancePolicy.getAccessTokenAudience(domainName, accessTokenRequest.isRoleInAudClaim(), tokenScopes));
        accessToken.setClientId(principalName);
        accessToken.setIssueTime(iat);
        accessToken.setAuthTime(iat);
        accessToken.setExpiryTime(iat + tokenTimeout);
        accessToken.setUserId(principalName);
        accessToken.setSubject(principalName);
        accessToken.setIssuer(services.issuerResolver.getAccessTokenIssuer(ctx.request(), accessTokenRequest.isUseOpenIDIssuer()));
        accessToken.setProxyPrincipal(proxyUser);
        accessToken.setScope(tokenScopes);
        accessToken.setAuthorizationDetails(accessTokenRequest.getAuthzDetails());
        accessToken.setPrincipalIssuer(principal.getIssuerIdentity());
        applyClaims(accessToken, decision, pr, caller, domainName, principalDomain);

        if (actor != null) {
            accessToken.setMayActEntry(AccessToken.CLAIM_SUBJECT, actor);
        }

        TokenIssuancePolicy.setAccessTokenConfirmation(accessToken, principal, accessTokenRequest);

        ServerPrivateKey privateKey = getSignPrivateKey(accessTokenRequest.getKeyType());
        String accessJwts = accessToken.getSignedToken(privateKey.getKey(), privateKey.getId(), privateKey.getAlgorithm());

        String idJwts = null;
        if (tokenScope.isOpenIdScope()) {

            final String serviceName = tokenScope.getServiceName();
            validate(serviceName, TYPE_SIMPLE_NAME, principalDomain, caller);

            IdToken idToken = new IdToken();
            idToken.setVersion(1);
            idToken.setAudience(tokenScope.getDomainName() + "." + serviceName);
            idToken.setSubject(principalName);
            idToken.setIssuer(services.issuerResolver.getAccessTokenIssuer(ctx.request(), accessTokenRequest.isUseOpenIDIssuer()));
            idToken.setPrincipalIssuer(principal.getIssuerIdentity());
            idToken.setIssueTime(iat);
            idToken.setAuthTime(iat);
            idToken.setExpiryTime(iat + TokenIssuancePolicy.determineAccessIdTokenTimeout(tokenTimeout, tokenConfig.getIdTokenMaxTimeout()));

            idJwts = idToken.getSignedToken(privateKey.getKey(), privateKey.getId(), privateKey.getAlgorithm());
        }

        AccessTokenResponse response = new AccessTokenResponse().setAccess_token(accessJwts)
                .setToken_type(TokenIssuancePolicy.accessTokenType(accessTokenRequest)).setExpires_in(tokenTimeout).setId_token(idJwts);

        if (scopeAdjusted || scopeDomainNames.size() > 1) {
            if (scopeDomainNames.size() == 1) {
                final String scopeDomainName = scopeDomainNames.iterator().next();
                response.setScope(TokenIssuancePolicy.generateScopeResponse(rolesByDomain.get(scopeDomainName),
                        scopeDomainName, tokenScope.isOpenIdScope()));
            } else {
                response.setScope(TokenIssuancePolicy.generateScopeResponse(tokenScopes, tokenScope.isOpenIdScope()));
            }
        }

        return response;
    }

    /**
     * Common part of the impersonation and delegation flows: resolve the
     * target domain, candidate roles and the exchange permissions.
     */
    static final class ExchangeResult {
        String requestDomainName;
        DataCache targetData;
        OAuth2Token subjectToken;
        String subjectPrincipal;
        Set<String> roles;
        ExternalPdpDecision decision;
    }

    ExchangeResult evaluateExchange(final ResourceContext ctx, final Principal principal,
            final AccessTokenRequest accessTokenRequest, final String principalDomain, final String caller,
            final PdpRequest pr, final String exchangeType) {

        ExchangeResult result = new ExchangeResult();
        final String requestDomainName = accessTokenRequest.getAudience();
        validate(requestDomainName, TYPE_DOMAIN_NAME, principalDomain, caller);

        DataCache targetData = services.dataStore.getDataCache(requestDomainName);
        if (targetData == null) {
            throw notFoundError("No such target domain: " + requestDomainName, caller,
                    ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }

        setRequestDomain(ctx, requestDomainName);

        OAuth2Token subjectToken = accessTokenRequest.getSubjectTokenObj();
        final String sourceDomainName = subjectToken.getAudience();
        if (services.dataStore.getDataCache(sourceDomainName) == null) {
            throw notFoundError("No such source domain: " + sourceDomainName, caller,
                    ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }

        String[] requestedRoles = TokenIssuancePolicy.tokenExchangeRequestedRoles(accessTokenRequest, subjectToken, requestDomainName);
        if (requestedRoles == null) {
            throw requestError("Invalid scope for token exchange", caller, requestDomainName, principalDomain);
        }

        final String subjectPrincipal = subjectToken.getSubject();
        final boolean impersonation = EXCHANGE_IMPERSONATION.equals(exchangeType);
        final String sourceResource = sourceDomainName + ":" + requestDomainName;
        final Subject clientSubject = builder.subject(principal);
        final Map<String, Object> context = requestContext(ctx, principal, accessTokenRequest, pr.requestId,
                requestDomainName, exchangeType, mode);
        ExternalPdpEvaluation evaluation = new ExternalPdpEvaluation(builder.subject(subjectPrincipal), context,
                AuthZenRequestBuilder.tokenResource(requestDomainName, Collections.singleton(requestDomainName)));

        Set<String> roles;
        if (mode == ExternalPdpMode.FILTER) {
            roles = new HashSet<>();
            services.dataStore.getAccessibleRoles(targetData, requestDomainName, subjectPrincipal,
                    requestedRoles, true, roles, false);
            if (roles.isEmpty()) {
                throw forbiddenError(TokenIssuancePolicy.tokenErrorMessage(caller, subjectPrincipal, requestDomainName,
                        requestedRoles), caller, requestDomainName, principalDomain);
            }
            if (impersonation && !services.authorizer.access(ZTSConsts.ZTS_ACTION_TOKEN_SOURCE_EXCHANGE,
                    sourceResource, principal, null)) {
                throw forbiddenError("Principal not authorized for token impersonation from source domain",
                        caller, requestDomainName, principalDomain);
            }
            for (String role : roles) {
                if (!services.authorizer.access(ZTSConsts.ZTS_ACTION_TOKEN_TARGET_EXCHANGE,
                        requestDomainName + ":" + ResourceUtils.roleResourceName(sourceDomainName, role),
                        principal, null)) {
                    throw forbiddenError("Principal not authorized for token exchange for the requested role",
                            caller, requestDomainName, principalDomain);
                }
                evaluation.addRole(KEY_SUBJECT, requestDomainName, role, true, Boolean.TRUE, null);
            }
        } else {
            roles = authoritativeRoles(targetData, requestDomainName, requestedRoles, pr,
                    caller, principalDomain);
            if (roles.isEmpty()) {
                throw forbiddenError(TokenIssuancePolicy.tokenErrorMessage(caller, subjectPrincipal, requestDomainName,
                        requestedRoles), caller, requestDomainName, principalDomain);
            }
            if (impersonation) {
                evaluation.addPermission(KEY_SOURCE_EXCHANGE, ZTSConsts.ZTS_ACTION_TOKEN_SOURCE_EXCHANGE,
                        sourceResource, clientSubject);
            }
            for (String role : roles) {
                evaluation.addRole(KEY_SUBJECT, requestDomainName, role, isRoleDefined(targetData, role), null, null);
                evaluation.addPermission(KEY_TARGET_EXCHANGE, ZTSConsts.ZTS_ACTION_TOKEN_TARGET_EXCHANGE,
                        requestDomainName + ":" + ResourceUtils.roleResourceName(sourceDomainName, role), clientSubject);
            }
        }

        ExternalPdpDecision decision = decide(evaluation, pr, caller, requestDomainName, principalDomain);
        if (!decision.isGatePermitted()) {
            throw forbiddenError(TokenIssuancePolicy.tokenErrorMessage(caller, subjectPrincipal, requestDomainName,
                    requestedRoles), caller, requestDomainName, principalDomain);
        }
        if (!decision.isPermissionGranted(KEY_SOURCE_EXCHANGE)) {
            throw forbiddenError("Principal not authorized for token impersonation from source domain",
                    caller, requestDomainName, principalDomain);
        }
        if (!decision.isPermissionGranted(KEY_TARGET_EXCHANGE)) {
            throw forbiddenError("Principal not authorized for token exchange for the requested role",
                    caller, requestDomainName, principalDomain);
        }
        Set<String> permittedRoles = decision.getPermittedRoles(KEY_SUBJECT, requestDomainName);
        if (permittedRoles.isEmpty()) {
            throw forbiddenError(TokenIssuancePolicy.tokenErrorMessage(caller, subjectPrincipal, requestDomainName,
                    requestedRoles), caller, requestDomainName, principalDomain);
        }
        pr.finalRoles = Collections.singletonMap(requestDomainName, permittedRoles);

        result.requestDomainName = requestDomainName;
        result.targetData = targetData;
        result.subjectToken = subjectToken;
        result.subjectPrincipal = subjectPrincipal;
        result.roles = permittedRoles;
        result.decision = decision;
        return result;
    }

    AccessTokenResponse processImpersonation(final ResourceContext ctx, final Principal principal,
            final AccessTokenRequest accessTokenRequest, final String principalDomain, final String caller,
            final PdpRequest pr) {

        ExchangeResult exchange = evaluateExchange(ctx, principal, accessTokenRequest, principalDomain, caller,
                pr, EXCHANGE_IMPERSONATION);
        final String requestDomainName = exchange.requestDomainName;
        final String principalName = principal.getFullName();

        long iat = System.currentTimeMillis() / 1000;
        int tokenTimeout = applyMaxExpiry(determineTokenExchangeTimeout(exchange.targetData, exchange.roles,
                accessTokenRequest, iat, principalDomain, caller), exchange.decision);

        AccessToken accessToken = new AccessToken();
        accessToken.setVersion(1);
        accessToken.setJwtId(UUID.randomUUID().toString());
        accessToken.setAudience(requestDomainName);
        accessToken.setClientId(principalName);
        accessToken.setIssueTime(iat);
        accessToken.setAuthTime(iat);
        accessToken.setExpiryTime(iat + tokenTimeout);
        accessToken.setUserId(principalName);
        accessToken.setSubject(exchange.subjectPrincipal);
        accessToken.setIssuer(services.issuerResolver.getAccessTokenIssuer(ctx.request(), accessTokenRequest.isUseOpenIDIssuer()));
        accessToken.setScope(new ArrayList<>(exchange.roles));
        accessToken.setPrincipalIssuer(principal.getIssuerIdentity());
        applyClaims(accessToken, exchange.decision, pr, caller, requestDomainName, principalDomain);

        setSpiffeClaim(accessToken, exchange.subjectToken, caller, requestDomainName, principalDomain);

        TokenIssuancePolicy.setAccessTokenConfirmation(accessToken, principal, accessTokenRequest);

        ServerPrivateKey privateKey = getSignPrivateKey(accessTokenRequest.getKeyType());
        String accessJwts = accessToken.getSignedToken(privateKey.getKey(), privateKey.getId(), privateKey.getAlgorithm());

        return new AccessTokenResponse().setAccess_token(accessJwts)
                .setToken_type(TokenIssuancePolicy.accessTokenType(accessTokenRequest)).setExpires_in(tokenTimeout)
                .setScope(TokenIssuancePolicy.generateScopeResponse(exchange.roles, requestDomainName, false));
    }

    void setSpiffeClaim(final AccessToken accessToken, final OAuth2Token subjectToken, final String caller,
            final String requestDomainName, final String principalDomain) {
        final String spiffeId = TokenIssuancePolicy.extractSpiffeIdFromToken(subjectToken);
        if (spiffeId != null) {
            TokenIssuancePolicy.verifySpiffeIdMatchesAthenzPrincipal(spiffeId, subjectToken.getSubject(),
                    caller, requestDomainName, principalDomain, services.spiffeUriManager, errors);
            accessToken.setCustomClaim(IdToken.CLAIM_SPIFFE, spiffeId);
        }
    }

    AccessTokenResponse processDelegation(final ResourceContext ctx, final Principal principal,
            final AccessTokenRequest accessTokenRequest, final String principalDomain, final String caller,
            final PdpRequest pr) {

        final OAuth2Token actorToken = accessTokenRequest.getActorTokenObj();
        if (!principal.getFullName().equals(actorToken.getSubject())) {
            throw forbiddenError("Request principal does not match actor token principal",
                    caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }

        final String actorTokenJkt = actorToken.getConfirmJwkThumbprint();
        if (actorTokenJkt != null && !actorTokenJkt.equals(accessTokenRequest.getDPoPJwkThumbprint())) {
            throw forbiddenError("DPoP proof key does not match actor token cnf.jkt",
                    caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }

        final String actor = accessTokenRequest.getActor();
        if (actor != null) {
            validate(actor, TYPE_SERVICE_NAME, principalDomain, caller);
        }

        ExchangeResult exchange = evaluateExchange(ctx, principal, accessTokenRequest, principalDomain, caller,
                pr, EXCHANGE_DELEGATION);
        final String requestDomainName = exchange.requestDomainName;
        final String principalName = principal.getFullName();

        long iat = System.currentTimeMillis() / 1000;
        int tokenTimeout = applyMaxExpiry(determineTokenExchangeTimeout(exchange.targetData, exchange.roles,
                accessTokenRequest, iat, principalDomain, caller), exchange.decision);

        AccessToken accessToken = new AccessToken();
        accessToken.setVersion(1);
        accessToken.setJwtId(UUID.randomUUID().toString());
        accessToken.setAudience(requestDomainName);
        accessToken.setClientId(principalName);
        accessToken.setIssueTime(iat);
        accessToken.setAuthTime(iat);
        accessToken.setExpiryTime(iat + tokenTimeout);
        accessToken.setUserId(principalName);
        accessToken.setSubject(exchange.subjectPrincipal);
        accessToken.setIssuer(services.issuerResolver.getAccessTokenIssuer(ctx.request(), accessTokenRequest.isUseOpenIDIssuer()));
        accessToken.setScope(new ArrayList<>(exchange.roles));
        accessToken.setPrincipalIssuer(principal.getIssuerIdentity());
        applyClaims(accessToken, exchange.decision, pr, caller, requestDomainName, principalDomain);

        if (actor != null) {
            accessToken.setMayActEntry(AccessToken.CLAIM_SUBJECT, actor);
        }

        setSpiffeClaim(accessToken, exchange.subjectToken, caller, requestDomainName, principalDomain);

        LinkedHashMap<String, Object> subjectActClaim = exchange.subjectToken.getAct();
        LinkedHashMap<String, Object> actClaim = new LinkedHashMap<>();
        actClaim.put(OAuth2Token.CLAIM_SUBJECT, actorToken.getSubject());
        if (subjectActClaim != null) {
            actClaim.put(OAuth2Token.CLAIM_ACT, subjectActClaim);
        }
        accessToken.setAct(actClaim);

        TokenIssuancePolicy.setAccessTokenConfirmation(accessToken, principal, accessTokenRequest);

        ServerPrivateKey privateKey = getSignPrivateKey(accessTokenRequest.getKeyType());
        String accessJwts = accessToken.getSignedToken(privateKey.getKey(), privateKey.getId(), privateKey.getAlgorithm());

        return new AccessTokenResponse().setAccess_token(accessJwts)
                .setToken_type(TokenIssuancePolicy.accessTokenType(accessTokenRequest)).setExpires_in(tokenTimeout)
                .setScope(TokenIssuancePolicy.generateScopeResponse(exchange.roles, requestDomainName, false));
    }

    AccessTokenResponse processJAGIssue(final ResourceContext ctx, final Principal principal,
            final AccessTokenRequest accessTokenRequest, final String principalDomain, final String caller,
            final PdpRequest pr) {

        TokenIssuancePolicy.disallowAuthorizedServicePrincipal(principal.getAuthorizedService(), "jag request",
                caller, principalDomain, errors);

        TokenIssuancePolicy.validateTokenAudienceNotRoleOrGroup(accessTokenRequest.getAudience(), principalDomain, caller, errors);

        String principalName = principal.getFullName();
        OAuth2Token subjectToken = accessTokenRequest.getSubjectTokenObj();

        TokenExchangeIdentityProvider identityProvider = services.providerConfigManager.getProvider(subjectToken.getIssuer());
        if (!principalName.equals(subjectToken.getAudience())) {
            final String clientId = services.dataStore.getServiceClientId(principal.getDomain(), principalName);
            final String tokenAudience = identityProvider == null ? subjectToken.getAudience() :
                    identityProvider.getTokenAudience(subjectToken);
            if ((clientId == null || !clientId.equals(tokenAudience)) &&
                    !TokenIssuancePolicy.isAuthenticatedUserSubjectToken(principal, tokenAudience, subjectToken,
                    identityProvider, services.userDomain)) {
                LOGGER.error("The subject token does not have expected audience: {}/{}", principalName,
                        tokenAudience);
                throw requestError("Invalid subject token audience", caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN,
                        principalDomain);
            }
        }

        AccessTokenScope tokenScope = new AccessTokenScope(accessTokenRequest.getScope(), principalDomain);
        final Set<String> scopeDomainNames = tokenScope.getDomainNames();
        final String requestDomainName = scopeDomainNames.iterator().next();
        setRequestDomain(ctx, requestDomainName);

        final String subjectIdentity = (identityProvider == null) ? subjectToken.getSubject() :
                identityProvider.getTokenIdentity(subjectToken);
        if (StringUtil.isEmpty(subjectIdentity)) {
            LOGGER.error("processJAGIssue: unable to extract subject identity from token");
            throw requestError("Invalid subject token - missing subject", caller, requestDomainName, principalDomain);
        }

        final Subject clientSubject = builder.subject(principal);
        final Map<String, Object> context = requestContext(ctx, principal, accessTokenRequest, pr.requestId,
                accessTokenRequest.getAudience(), null, mode);
        ExternalPdpEvaluation evaluation = new ExternalPdpEvaluation(builder.subject(subjectIdentity), context,
                AuthZenRequestBuilder.tokenResource(accessTokenRequest.getAudience(), scopeDomainNames));

        Map<String, DataCache> dataByDomain = new HashMap<>();
        for (String domainName : scopeDomainNames) {

            validate(domainName, TYPE_DOMAIN_NAME, principalDomain, caller);

            String[] requestedRoles = tokenScope.getRoleNames(domainName);
            if (requestedRoles == null) {
                throw requestError("Scope value does not contain any roles", caller, domainName, principalDomain);
            }
            for (String requestedRole : requestedRoles) {
                validate(requestedRole, TYPE_ENTITY_NAME, principalDomain, caller);
            }

            DataCache data = services.dataStore.getDataCache(domainName);
            if (data == null) {
                setRequestDomain(ctx, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
                throw notFoundError("No such domain: " + domainName, caller,
                        ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
            }
            dataByDomain.put(domainName, data);

            if (mode == ExternalPdpMode.FILTER) {
                Set<String> subjectRoles = new HashSet<>();
                services.dataStore.getAccessibleRoles(data, domainName, subjectIdentity, requestedRoles, true,
                        subjectRoles, false);
                if (subjectRoles.isEmpty()) {
                    throw forbiddenError(TokenIssuancePolicy.tokenErrorMessage(caller, subjectIdentity, domainName, requestedRoles),
                            caller, domainName, principalDomain);
                }
                for (String subjectRole : subjectRoles) {
                    if (!services.authorizer.access(ZTSConsts.ZTS_ACTION_JAG_EXCHANGE,
                            ResourceUtils.roleResourceName(domainName, subjectRole), principal, null)) {
                        throw forbiddenError("Principal not authorized for token exchange for the requested role",
                                caller, domainName, principalDomain);
                    }
                    evaluation.addRole(KEY_SUBJECT, domainName, subjectRole, true, Boolean.TRUE, null);
                }
            } else {
                Set<String> subjectRoles = authoritativeRoles(data, domainName, requestedRoles, pr,
                        caller, principalDomain);
                if (subjectRoles.isEmpty()) {
                    throw forbiddenError(TokenIssuancePolicy.tokenErrorMessage(caller, subjectIdentity, domainName, requestedRoles),
                            caller, domainName, principalDomain);
                }
                for (String subjectRole : subjectRoles) {
                    evaluation.addRole(KEY_SUBJECT, domainName, subjectRole, isRoleDefined(data, subjectRole), null, null);
                    evaluation.addPermission(KEY_TARGET_EXCHANGE, ZTSConsts.ZTS_ACTION_JAG_EXCHANGE,
                            ResourceUtils.roleResourceName(domainName, subjectRole), clientSubject);
                }
            }
        }

        ExternalPdpDecision decision = decide(evaluation, pr, caller, requestDomainName, principalDomain);
        if (!decision.isGatePermitted()) {
            throw forbiddenError(TokenIssuancePolicy.tokenErrorMessage(caller, subjectIdentity, requestDomainName, null),
                    caller, requestDomainName, principalDomain);
        }
        if (!decision.isPermissionGranted(KEY_TARGET_EXCHANGE)) {
            throw forbiddenError("Principal not authorized for token exchange for the requested role",
                    caller, requestDomainName, principalDomain);
        }

        Map<String, Set<String>> subjectRolesByDomain = new HashMap<>();
        int tokenTimeout = Integer.MAX_VALUE;
        for (String domainName : scopeDomainNames) {
            Set<String> subjectRoles = decision.getPermittedRoles(KEY_SUBJECT, domainName);
            if (subjectRoles.isEmpty()) {
                throw forbiddenError(TokenIssuancePolicy.tokenErrorMessage(caller, subjectIdentity, domainName,
                        tokenScope.getRoleNames(domainName)), caller, domainName, principalDomain);
            }
            subjectRolesByDomain.put(domainName, subjectRoles);
            int domainTokenTimeout = determineTokenTimeout(dataByDomain.get(domainName), subjectRoles, null,
                    accessTokenRequest.getExpiryTime());
            tokenTimeout = Math.min(tokenTimeout, domainTokenTimeout);
        }
        tokenTimeout = applyMaxExpiry(tokenTimeout, decision);
        pr.finalRoles = subjectRolesByDomain;

        List<String> roleList = TokenIssuancePolicy.generateAccessTokenScopeList(subjectRolesByDomain, null);
        long iat = System.currentTimeMillis() / 1000;

        AccessToken accessToken = new AccessToken();
        accessToken.setVersion(1);
        accessToken.setJwtId(UUID.randomUUID().toString());
        accessToken.setAudience(accessTokenRequest.getAudience());
        accessToken.setClientId(principalName);
        accessToken.setIssueTime(iat);
        accessToken.setAuthTime(iat);
        accessToken.setExpiryTime(iat + tokenTimeout);
        accessToken.setSubject(subjectIdentity);
        accessToken.setIssuer(services.issuerResolver.getAccessTokenIssuer(ctx.request(), true));
        accessToken.setScope(roleList);
        accessToken.setResource(accessTokenRequest.getResource());
        accessToken.setPrincipalIssuer(principal.getIssuerIdentity());
        applyClaims(accessToken, decision, pr, caller, requestDomainName, principalDomain);

        if (identityProvider != null && identityProvider.getTokenExchangeClaims() != null) {
            for (String claim : identityProvider.getTokenExchangeClaims()) {
                accessToken.setCustomClaim(claim, subjectToken.getClaim(claim));
            }
        }

        ServerPrivateKey privateKey = getSignPrivateKey(accessTokenRequest.getKeyType());
        String accessJwts = accessToken.getSignedToken(privateKey.getKey(), privateKey.getId(),
                privateKey.getAlgorithm(), AccessToken.HDR_TOKEN_JAG);

        TokenIssuancePolicy.setJAGAccessLogData(ctx, accessTokenRequest, principal, subjectIdentity, accessToken.getJwtId());

        return new AccessTokenResponse().setAccess_token(accessJwts).setToken_type(OAUTH_NA_TOKEN)
                .setIssued_token_type(OAUTH_JAG_TOKEN).setExpires_in(tokenTimeout)
                .setScope(TokenIssuancePolicy.generateScopeResponse(roleList, false));
    }

    AccessTokenResponse processJAGExchange(final ResourceContext ctx, final Principal principal,
            final AccessTokenRequest accessTokenRequest, final String clientPrincipalDomain, final String caller,
            final PdpRequest pr) {

        TokenIssuancePolicy.disallowAuthorizedServicePrincipal(principal.getAuthorizedService(), "jag token exchange",
                caller, clientPrincipalDomain, errors);

        AccessToken jagToken = accessTokenRequest.getJagTokenObj();

        final String jagAudience = jagToken.getAudience();
        if (!services.issuerResolver.isOauth2Issuer(jagAudience)) {
            LOGGER.error("Invalid jag assertion aud claim: {}", jagAudience);
            throw requestError("Unknown jag assertion audience", caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN,
                    clientPrincipalDomain);
        }

        final String clientPrincipalName = principal.getFullName();
        if (!clientPrincipalName.equals(jagToken.getClientId())) {
            final String clientId = services.dataStore.getServiceClientId(clientPrincipalDomain, clientPrincipalName);
            if (clientId == null || !clientId.equals(jagToken.getClientId())) {
                LOGGER.error("Invalid jag assertion client_id claim: {}, clientPrincipalDomain {}, clientPrincipalName {}, clientId {}",
                        jagToken.getClientId(), clientPrincipalDomain, clientPrincipalName, clientId);
                throw requestError("Invalid jag assertion client_id", caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN,
                        clientPrincipalDomain);
            }
        }

        final String actor = accessTokenRequest.getActor();
        if (actor != null) {
            validate(actor, TYPE_SERVICE_NAME, clientPrincipalDomain, caller);
            if (principal.getX509Certificate() == null) {
                throw forbiddenError("Actor parameter requires X.509 authenticated principal",
                        caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN, clientPrincipalDomain);
            }
        }

        String scopeStd = jagToken.getScopeStd();
        if (StringUtil.isBlank(scopeStd)) {
            LOGGER.error("Invalid jag assertion - missing scope");
            throw requestError("Invalid jag assertion - missing scope", caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN,
                    clientPrincipalDomain);
        }
        String requestedScope = accessTokenRequest.getScope();
        if (!StringUtil.isBlank(requestedScope)) {
            final Set<String> requestedSet = new LinkedHashSet<>(Arrays.asList(requestedScope.trim().split("\\s+")));
            final Set<String> assertionSet = new LinkedHashSet<>(Arrays.asList(scopeStd.split("\\s+")));
            if (!assertionSet.containsAll(requestedSet)) {
                LOGGER.error("Requested scope is not a subset of assertion scope. Requested: {}, Assertion: {}",
                        requestedSet, assertionSet);
                throw requestError("Invalid request: requested scope is not a subset of assertion scope",
                        caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN, clientPrincipalDomain);
            }
            scopeStd = String.join(" ", requestedSet);
        }

        TokenExchangeIdentityProvider identityProvider = services.providerConfigManager.getProvider(jagToken.getIssuer());
        String principalName = (identityProvider == null) ? jagToken.getSubject() :
                identityProvider.getTokenIdentity(jagToken);
        if (StringUtil.isEmpty(principalName)) {
            LOGGER.error("Invalid jag assertion - missing subject");
            throw requestError("Invalid jag assertion - missing subject", caller, ZTSConsts.ZTS_UNKNOWN_DOMAIN,
                    clientPrincipalDomain);
        }

        final String principalDomain = AthenzUtils.extractPrincipalDomainName(principalName);
        AccessTokenScope tokenScope = new AccessTokenScope(scopeStd, principalDomain);

        Set<String> scopeDomainNames = tokenScope.getDomainNames();
        final String requestAudience = accessTokenRequest.getAudience();
        if (scopeDomainNames.size() > 1 && StringUtil.isEmpty(requestAudience)) {
            throw requestError("Multiple scope domains require an audience", caller,
                    ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
        }

        final String domainName = scopeDomainNames.size() == 1 ? tokenScope.getDomainName() :
                requestAudience.toLowerCase();
        setRequestDomain(ctx, domainName);
        validate(domainName, TYPE_DOMAIN_NAME, principalDomain, caller);
        if (!scopeDomainNames.contains(domainName)) {
            throw requestError("Audience domain must be one of the scope domains", caller,
                    domainName, principalDomain);
        }

        final Subject tokenSubject = builder.subject(principalName);
        final Map<String, Object> context = requestContext(ctx, principal, accessTokenRequest, pr.requestId,
                domainName, null, mode);
        ExternalPdpEvaluation evaluation = new ExternalPdpEvaluation(tokenSubject, context,
                AuthZenRequestBuilder.tokenResource(domainName, scopeDomainNames));

        Map<String, DataCache> dataByDomain = new HashMap<>();
        Map<String, String[]> requestedByDomain = new HashMap<>();
        for (String scopeDomainName : scopeDomainNames) {

            validate(scopeDomainName, TYPE_DOMAIN_NAME, principalDomain, caller);

            String[] requestedRoles = tokenScope.getRoleNames(scopeDomainName);
            if (requestedRoles != null) {
                for (String requestedRole : requestedRoles) {
                    validate(requestedRole, TYPE_ENTITY_NAME, principalDomain, caller);
                }
            }

            DataCache data = services.dataStore.getDataCache(scopeDomainName);
            if (data == null) {
                setRequestDomain(ctx, ZTSConsts.ZTS_UNKNOWN_DOMAIN);
                throw notFoundError("No such domain: " + scopeDomainName, caller,
                        ZTSConsts.ZTS_UNKNOWN_DOMAIN, principalDomain);
            }
            dataByDomain.put(scopeDomainName, data);
            requestedByDomain.put(scopeDomainName, requestedRoles);

            Set<String> roles;
            if (mode == ExternalPdpMode.FILTER) {
                roles = new HashSet<>();
                services.dataStore.getAccessibleRoles(data, scopeDomainName, principalName, requestedRoles, true,
                        roles, false);
            } else {
                roles = authoritativeRoles(data, scopeDomainName, requestedRoles, pr,
                        caller, principalDomain);
            }
            if (roles.isEmpty()) {
                throw forbiddenError(TokenIssuancePolicy.tokenErrorMessage(caller, principalName, scopeDomainName, requestedRoles),
                        caller, scopeDomainName, principalDomain);
            }
            for (String role : roles) {
                evaluation.addRole(KEY_SUBJECT, scopeDomainName, role,
                        mode == ExternalPdpMode.FILTER || isRoleDefined(data, role),
                        mode == ExternalPdpMode.FILTER ? Boolean.TRUE : null, null);
            }
        }

        ExternalPdpDecision decision = decide(evaluation, pr, caller, domainName, principalDomain);
        if (!decision.isGatePermitted()) {
            throw forbiddenError(TokenIssuancePolicy.tokenErrorMessage(caller, principalName, domainName,
                    requestedByDomain.get(domainName)), caller, domainName, principalDomain);
        }

        Map<String, Set<String>> rolesByDomain = new HashMap<>();
        int tokenTimeout = Integer.MAX_VALUE;
        boolean scopeAdjusted = false;
        for (String scopeDomainName : scopeDomainNames) {
            final String[] requestedRoles = requestedByDomain.get(scopeDomainName);
            Set<String> roles = decision.getPermittedRoles(KEY_SUBJECT, scopeDomainName);
            if (roles.isEmpty()) {
                throw forbiddenError(TokenIssuancePolicy.tokenErrorMessage(caller, principalName, scopeDomainName, requestedRoles),
                        caller, scopeDomainName, principalDomain);
            }
            rolesByDomain.put(scopeDomainName, roles);
            int domainTokenTimeout = determineTokenTimeout(dataByDomain.get(scopeDomainName), roles, null,
                    services.userDomain.equals(principalDomain) ? tokenConfig.getJagTokenUserMaxTimeout()
                            : tokenConfig.getJagTokenServiceMaxTimeout());
            tokenTimeout = Math.min(tokenTimeout, domainTokenTimeout);
            if (tokenScope.sendScopeResponse() || requestedRoles != null && requestedRoles.length != roles.size()) {
                scopeAdjusted = true;
            }
        }
        tokenTimeout = applyMaxExpiry(tokenTimeout, decision);
        pr.finalRoles = rolesByDomain;

        long iat = System.currentTimeMillis() / 1000;

        List<String> roleList = TokenIssuancePolicy.generateAccessTokenScopeList(rolesByDomain,
                accessTokenRequest.isFullArn() ? null : domainName);

        String audience;
        if (accessTokenRequest.isRoleInAudClaim() && accessTokenRequest.isFullArn() && roleList.size() == 1) {
            validate(requestAudience, TYPE_SERVICE_NAME, principalDomain, caller);
            audience = requestAudience + ":" + roleList.get(0);
        } else if (accessTokenRequest.isFullArn() && !StringUtil.isEmpty(requestAudience)) {
            TokenIssuancePolicy.validateTokenAudienceNotRoleOrGroup(requestAudience, principalDomain, caller, errors);
            audience = requestAudience;
        } else {
            audience = domainName;
        }

        AccessToken accessToken = new AccessToken();
        accessToken.setVersion(1);
        accessToken.setJwtId(UUID.randomUUID().toString());
        accessToken.setAudience(audience);
        accessToken.setClientId(clientPrincipalName);
        accessToken.setIssueTime(iat);
        accessToken.setAuthTime(iat);
        accessToken.setExpiryTime(iat + tokenTimeout);
        accessToken.setUserId(principalName);
        accessToken.setSubject(principalName);
        accessToken.setIssuer(services.issuerResolver.getAccessTokenIssuer(ctx.request(), accessTokenRequest.isUseOpenIDIssuer()));
        accessToken.setScope(roleList);
        accessToken.setPrincipalIssuer(principal.getIssuerIdentity());
        applyClaims(accessToken, decision, pr, caller, domainName, principalDomain);

        if (actor != null) {
            accessToken.setMayActEntry(AccessToken.CLAIM_SUBJECT, actor);
            accessToken.setActEntry(AccessToken.CLAIM_SUBJECT, clientPrincipalName);
        }

        if (identityProvider != null && identityProvider.getTokenExchangeClaims() != null) {
            for (String claim : identityProvider.getTokenExchangeClaims()) {
                if (IdToken.CLAIM_GROUPS.equals(claim)) {
                    accessToken.setCustomClaim(claim, accessToken.getScope());
                } else {
                    accessToken.setCustomClaim(claim, jagToken.getClaim(claim));
                }
            }
        }

        TokenIssuancePolicy.setAccessTokenConfirmation(accessToken, principal, accessTokenRequest);

        ServerPrivateKey privateKey = getSignPrivateKey(accessTokenRequest.getKeyType());
        String accessJwts = accessToken.getSignedToken(privateKey.getKey(), privateKey.getId(), privateKey.getAlgorithm());

        TokenIssuancePolicy.setJAGAccessLogData(ctx, accessTokenRequest, principal, principalName, accessToken.getJwtId());

        AccessTokenResponse response = new AccessTokenResponse().setAccess_token(accessJwts)
                .setToken_type(TokenIssuancePolicy.accessTokenType(accessTokenRequest)).setExpires_in(tokenTimeout);

        if (scopeAdjusted || scopeDomainNames.size() > 1) {
            if (scopeDomainNames.size() == 1) {
                response.setScope(TokenIssuancePolicy.generateScopeResponse(rolesByDomain.get(domainName), domainName, false));
            } else {
                response.setScope(TokenIssuancePolicy.generateScopeResponse(roleList, false));
            }
        }
        return response;
    }

    // AUDIT mode: the legacy path issues the token unmodified; the PDP
    // request is built on the request thread and evaluated asynchronously

    AccessTokenResponse processAudit(final ResourceContext ctx, final Principal principal,
            final AccessTokenRequest accessTokenRequest, final String principalDomain, final String caller) {
        AccessTokenResponse response;
        try {
            response = services.legacyFlow.process(ctx, principal, accessTokenRequest, principalDomain, caller);
        } catch (RuntimeException ex) {
            submitShadow(ctx, principal, accessTokenRequest, principalDomain, null,
                    ex instanceof ResourceException ? ((ResourceException) ex).getCode() : ResourceException.INTERNAL_SERVER_ERROR);
            throw ex;
        }
        submitShadow(ctx, principal, accessTokenRequest, principalDomain, response, ResourceException.OK);
        return response;
    }

    void submitShadow(final ResourceContext ctx, final Principal principal, final AccessTokenRequest accessTokenRequest,
            final String principalDomain, final AccessTokenResponse response, int legacyStatus) {

        final String flow = flowName(accessTokenRequest);
        final ExternalPdpEvaluation evaluation;
        final Map<String, Set<String>> issuedRoles;
        try {
            final String audience = getRequestDomainName(ctx);
            issuedRoles = response == null ? requestedRoles(accessTokenRequest, principalDomain)
                    : issuedRoles(response.getAccess_token(), audience);
            final String subjectName = response == null ? shadowSubjectName(accessTokenRequest, principal)
                    : issuedSubject(response.getAccess_token(), principal);
            final Subject subject = subjectName.equals(principal.getFullName()) ? builder.subject(principal)
                    : builder.subject(subjectName);
            final String requestId = UUID.randomUUID().toString();
            evaluation = new ExternalPdpEvaluation(subject, requestContext(ctx, principal, accessTokenRequest,
                    requestId, audience, null, ExternalPdpMode.AUDIT),
                    AuthZenRequestBuilder.tokenResource(audience == null ? "" : audience, issuedRoles.keySet()));
            for (Map.Entry<String, Set<String>> entry : issuedRoles.entrySet()) {
                final DataCache data = services.dataStore.getDataCache(entry.getKey());
                for (String role : entry.getValue()) {
                    evaluation.addRole(KEY_SUBJECT, entry.getKey(), role, data != null && isRoleDefined(data, role),
                            config.getAuditTarget() == ExternalPdpMode.FILTER ? Boolean.valueOf(response != null) : null,
                            null);
                }
            }
            final boolean queued = manager.submitAudit(() -> runShadow(evaluation, issuedRoles, legacyStatus,
                    requestId, flow, principal.getFullName(), audience));
            if (!queued) {
                services.metric.increment(METRIC_EVAL, "mode", mode.name(), "flow", flow, "outcome", OUTCOME_AUDIT_DROPPED);
            }
        } catch (RuntimeException | java.text.ParseException ex) {
            LOGGER.error("Unable to build external PDP audit request: {}", ex.getMessage());
        }
    }

    void runShadow(final ExternalPdpEvaluation evaluation, final Map<String, Set<String>> issuedRoles,
            int legacyStatus, final String requestId, final String flow, final String principalName,
            final String audience) {

        ExternalPdpDecisionLog log = new ExternalPdpDecisionLog(requestId, mode, flow)
                .with("audit_target", config.getAuditTarget().name())
                .with("principal", principalName)
                .with("audience", audience)
                .with("legacy_status", legacyStatus)
                .with("legacy_roles", issuedRoles);
        String diff;
        try {
            ExternalPdpDecision decision = evaluation.decide(
                    manager.evaluations(evaluation.toRequest(), manager.newDeadline()));
            diff = auditDiff(decision, issuedRoles, legacyStatus == ResourceException.OK);
            log.with("gate", decision.isGatePermitted())
                    .with("permitted_roles", decision.getPermittedRoles())
                    .with("max_expires_in", decision.getMaxExpiresIn())
                    .with("claim_names", decision.getClaims() == null ? null : new ArrayList<>(decision.getClaims().keySet()))
                    .with("reasons", decision.getReasons().isEmpty() ? null : decision.getReasons());
        } catch (ExternalPdpException ex) {
            diff = ex.getCode() == ExternalPdpException.Code.TIMEOUT ? OUTCOME_TIMEOUT : OUTCOME_ERROR;
            log.with("error_code", ex.getCode());
        }
        log.with("outcome", diff).write();
        services.metric.increment(METRIC_AUDIT_DIFF, "flow", flow, "outcome", diff);
    }

    static String auditDiff(final ExternalPdpDecision decision, final Map<String, Set<String>> issuedRoles,
            boolean legacyIssued) {
        boolean anyPermitted = false;
        boolean allPermitted = true;
        for (Map.Entry<String, Set<String>> entry : issuedRoles.entrySet()) {
            Set<String> permitted = decision.getPermittedRoles(KEY_SUBJECT, entry.getKey());
            anyPermitted |= !permitted.isEmpty();
            allPermitted &= permitted.containsAll(entry.getValue());
        }
        if (!legacyIssued) {
            return decision.isGatePermitted() && anyPermitted ? "pdp_permit_legacy_deny" : "match_deny";
        }
        if (!decision.isGatePermitted() || !anyPermitted) {
            return "pdp_deny";
        }
        return allPermitted ? "match" : "pdp_narrower";
    }

    static Map<String, Set<String>> issuedRoles(final String accessToken, final String audience)
            throws java.text.ParseException {
        JWTClaimsSet claims = SignedJWT.parse(accessToken).getJWTClaimsSet();
        Map<String, Set<String>> roles = new TreeMap<>();
        List<String> scopes = claims.getStringListClaim(AccessToken.CLAIM_SCOPE);
        if (scopes == null) {
            return roles;
        }
        for (String scope : scopes) {
            final int idx = scope.indexOf(":role.");
            if (idx > 0) {
                roles.computeIfAbsent(scope.substring(0, idx), d -> new TreeSet<>()).add(scope.substring(idx + 6));
            } else if (audience != null) {
                roles.computeIfAbsent(audience, d -> new TreeSet<>()).add(scope);
            }
        }
        return roles;
    }

    static String issuedSubject(final String accessToken, final Principal principal) throws java.text.ParseException {
        final String subject = SignedJWT.parse(accessToken).getJWTClaimsSet().getSubject();
        return subject == null ? principal.getFullName() : subject;
    }

    static Map<String, Set<String>> requestedRoles(final AccessTokenRequest accessTokenRequest,
            final String principalDomain) {
        Map<String, Set<String>> roles = new TreeMap<>();
        if (StringUtil.isEmpty(accessTokenRequest.getScope())) {
            return roles;
        }
        AccessTokenScope tokenScope = new AccessTokenScope(accessTokenRequest.getScope(), principalDomain);
        for (String domainName : tokenScope.getDomainNames()) {
            String[] requested = tokenScope.getRoleNames(domainName);
            if (requested != null) {
                roles.put(domainName, new TreeSet<>(Arrays.asList(requested)));
            }
        }
        return roles;
    }

    static String shadowSubjectName(final AccessTokenRequest accessTokenRequest, final Principal principal) {
        final OAuth2Token token = accessTokenRequest.getRequestType() == RequestType.JAG_JWT_BEARER
                ? accessTokenRequest.getJagTokenObj() : accessTokenRequest.getSubjectTokenObj();
        if (token != null && !StringUtil.isEmpty(token.getSubject())) {
            return token.getSubject();
        }
        return principal.getFullName();
    }

    @Override
    public void close() {
        manager.close();
    }
}
