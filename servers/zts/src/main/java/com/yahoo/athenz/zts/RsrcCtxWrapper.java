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
package com.yahoo.athenz.zts;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.common.ServerCommonConsts;
import com.yahoo.athenz.common.messaging.DomainChangeMessage;
import com.yahoo.athenz.common.server.rest.Http;
import com.yahoo.athenz.common.metrics.Metric;
import jakarta.servlet.ServletContext;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import java.security.cert.X509Certificate;
import java.util.List;

public class RsrcCtxWrapper implements ResourceContext {

    private static final Logger LOG = LoggerFactory.getLogger(RsrcCtxWrapper.class);

    com.yahoo.athenz.common.server.rest.ResourceContext ctx;
    boolean optionalAuth;
    Metric metric;
    private final Object timerMetric;
    private final String apiName;

    public RsrcCtxWrapper(ServletContext servletContext, HttpServletRequest request, HttpServletResponse response,
                          Http.AuthorityList authList, boolean optionalAuth, Authorizer authorizer,
                          Metric metric, Object timerMetric, String apiName) {
        this.optionalAuth = optionalAuth;
        this.metric = metric;
        this.timerMetric = timerMetric;
        this.apiName = apiName.toLowerCase();
        ctx = new com.yahoo.athenz.common.server.rest.ResourceContext(servletContext, request, response,
                authList, authorizer);
    }

    public com.yahoo.athenz.common.server.rest.ResourceContext context() {
        return ctx;
    }

    public Principal principal() {
        return ctx.principal();
    }

    public String getRequestDomain() {
        return ctx.getRequestDomain();
    }

    public Object getTimerMetric() {
        return timerMetric;
    }

    public void setRequestDomain(String requestDomain) {
        ctx.setRequestDomain(requestDomain);
    }

    @Override
    public HttpServletRequest request() {
        return ctx.request();
    }

    @Override
    public HttpServletResponse response() {
        return ctx.response();
    }

    @Override
    public ServletContext servletContext() {
        return ctx.servletContext();
    }

    @Override
    public String getApiName() {
        return apiName;
    }

    @Override
    public String getHttpMethod() {
        return ctx.request().getMethod();
    }

    @Override
    public void authenticate() {
        try {
            ctx.authenticate(optionalAuth);
            // For ZTS, prevent authentication with mTLS restricted certs
            final Principal principal = principal();
            if (principal != null && principal.getMtlsRestricted()) {
                LOG.error("authenticate: certificate is mTLS restricted");
                throw new com.yahoo.athenz.common.server.rest.ResourceException(com.yahoo.athenz.common.server.rest.ResourceException.UNAUTHORIZED, "certificate is mTLS restricted");
            }
        } catch (com.yahoo.athenz.common.server.rest.ResourceException restExc) {
            throwZtsException(restExc);
        }
    }
    
    @Override
    public void authorize(String action, String resource, String trustedDomain) {
        try {
            ctx.authorize(action, resource, trustedDomain);
        } catch (com.yahoo.athenz.common.server.rest.ResourceException restExc) {
            logPrincipal();
            throwZtsException(restExc);
        }
    }

    @Override
    public void addDomainChangeMessage(DomainChangeMessage domainChangeMsg) {
    }

    @Override
    public List<DomainChangeMessage> getDomainChangeMessages() {
        return null;
    }

    public String logPrincipal() {
        final Principal principal = ctx.principal();
        if (principal == null) {
            return null;
        }
        // we'll try our role principal name and if it's not configured
        // we'll fall back to our service principal name
        String principalName = principal.getRolePrincipalName();
        if (principalName == null) {
            principalName = principal.getFullName();
        }
        if (ctx.request() != null) {
            logPrincipal(principalName);
            logAuthorityId(principal.getAuthority());
            logCertificateSerialNumber(principal.getX509Certificate());
        }
        return principalName;
    }

    public void logCertificateSerialNumber(X509Certificate x509Cert) {
        if (x509Cert == null) {
            return;
        }
        ctx.request().setAttribute(ServerCommonConsts.REQUEST_X509_SERIAL, x509Cert.getSerialNumber().toString());
    }

    public void logPrincipal(final String principal) {
        if (principal == null) {
            return;
        }
        ctx.request().setAttribute(ServerCommonConsts.REQUEST_PRINCIPAL, principal);
    }

    public void logAuthorityId(Authority authority) {
        if (authority == null) {
            return;
        }
        ctx.request().setAttribute(ServerCommonConsts.REQUEST_AUTHORITY_ID, authority.getID());
    }

    public String getPrincipalDomain() {
        final Principal principal = ctx.principal();
        return (principal == null) ? null : principal.getDomain();
    }

    public void throwZtsException(com.yahoo.athenz.common.server.rest.ResourceException restExc) {

        metric.increment("authfailure");

        // first check to see if this is an auth failure and if
        // that's the case include the WWW-Authenticate challenge

       ctx.sendAuthenticateChallenges(restExc);

        // now throw a ZTS exception based on the rest exception

        String msg = null;
        Object data = restExc.getData();
        if (data instanceof String) {
            msg = (String) data;
        }
        if (msg == null) {
            msg = restExc.getMessage();
        }
        throw new com.yahoo.athenz.zts.ResourceException(restExc.getCode(),
                new ResourceError().code(restExc.getCode()).message(msg));
    }
}
