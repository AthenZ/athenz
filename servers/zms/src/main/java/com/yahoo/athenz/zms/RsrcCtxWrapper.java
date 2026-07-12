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
package com.yahoo.athenz.zms;

import com.yahoo.athenz.common.server.rest.ServerResourceContext;
import com.yahoo.athenz.common.server.ServerResourceException;
import com.yahoo.athenz.zms.utils.ZMSUtils;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.common.ServerCommonConsts;
import com.yahoo.athenz.common.messaging.DomainChangeMessage;
import com.yahoo.athenz.common.server.rest.Http;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class RsrcCtxWrapper implements ResourceContext {

    private static final Logger LOG = LoggerFactory.getLogger(RsrcCtxWrapper.class);

    private final ServerResourceContext ctx;
    private final Object timerMetric;
    private final boolean optionalAuth;
    private final String apiName;
    private final boolean eventPublishersEnabled;
    private final Authority userAuthority;
    private final String userDomain;
    private boolean principalValidated = false;
    private List<DomainChangeMessage> domainChangeMessages;

    RsrcCtxWrapper(ServletContext servletContext, HttpServletRequest request, HttpServletResponse response,
                   Http.AuthorityList authList, boolean optionalAuth, Authorizer authorizer, Object timerMetric,
                   final String apiName, boolean eventPublishersEnabled,
                   Authority userAuthority, String userDomain) {
        this.optionalAuth = optionalAuth;
        this.timerMetric = timerMetric;
        this.apiName = apiName.toLowerCase();
        this.eventPublishersEnabled = eventPublishersEnabled;
        this.userAuthority = userAuthority;
        this.userDomain = userDomain;
        ctx = new ServerResourceContext(servletContext, request,
                response, authList, authorizer);
    }

    ServerResourceContext context() {
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
    public String getApiName() {
        return apiName;
    }

    @Override
    public String getHttpMethod() {
        return ctx.request().getMethod();
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
    public void authenticate() {
        try {
            ctx.authenticate(optionalAuth);
            validateUserPrincipal(principal());
        } catch (ServerResourceException restExc) {
            throwZmsException(restExc);
        }
    }

    @Override
    public void authorize(String action, String resource, String trustedDomain) {
        try {
            ctx.authorize(action, resource, trustedDomain);
            validateUserPrincipal(principal());
        } catch (ServerResourceException restExc) {
            logPrincipal();
            throwZmsException(restExc);
        }
    }

    void validateUserPrincipal(final Principal principal) throws ServerResourceException {
        if (principalValidated || principal == null || userAuthority == null || userDomain == null) {
            return;
        }
        principalValidated = true;
        if (!userDomain.equals(principal.getDomain())) {
            return;
        }
        if (userAuthority.getUserType(principal.getFullName()) != Authority.UserType.USER_ACTIVE) {
            LOG.error("validateUserPrincipal: user {} is not valid", principal.getFullName());
            throw new ServerResourceException(ServerResourceException.UNAUTHORIZED, "user is not valid");
        }
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
        ctx.request().setAttribute(ServerCommonConsts.REQUEST_PRINCIPAL, principalName);
        logAuthorityId(principal.getAuthority());
        logCertificateSerialNumber(principal.getX509Certificate());
        return principalName;
    }

    public void logCertificateSerialNumber(X509Certificate x509Cert) {
        if (x509Cert == null) {
            return;
        }
        ctx.request().setAttribute(ServerCommonConsts.REQUEST_X509_SERIAL, x509Cert.getSerialNumber().toString());
    }

    public void logAuthorityId(Authority authority) {
        if (authority == null) {
            return;
        }
        ctx.request().setAttribute(ServerCommonConsts.REQUEST_AUTHORITY_ID, authority.getID());
    }

    void throwZmsException(ServerResourceException restExc) {

        // first check to see if this is an auth failure and if
        // that's the case include the WWW-Authenticate challenge

        ctx.sendAuthenticateChallenges(restExc);

        // now throw a ZMS exception based on the rest exception

        throw ZMSUtils.error(restExc);
    }

    public void addDomainChangeMessage(DomainChangeMessage domainChangeMsg) {

        // if we have no event publishers configured there is no
        // point of creating event objects

        if (!eventPublishersEnabled) {
            return;
        }

        if (domainChangeMessages == null) {
            domainChangeMessages = new ArrayList<>();
        }
        
        if (isNewTypeMessage(domainChangeMsg)) {
            domainChangeMessages.add(domainChangeMsg);
        }
    }

    private boolean isNewTypeMessage(DomainChangeMessage domainChangeMsg) {
        for (DomainChangeMessage existMsg : domainChangeMessages) {
            if (existMsg.getDomainName().equals(domainChangeMsg.getDomainName()) && existMsg.getObjectType() == domainChangeMsg.getObjectType()) {
                return false;
            }
        }
        return true;
    }

    public List<DomainChangeMessage> getDomainChangeMessages() {
        return domainChangeMessages;
    }
}
