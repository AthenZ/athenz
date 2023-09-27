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

import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.common.ServerCommonConsts;
import com.yahoo.athenz.common.messaging.DomainChangeMessage;
import com.yahoo.athenz.common.server.rest.Http;

import java.security.cert.X509Certificate;
import java.util.ArrayList;
import java.util.List;

public class RsrcCtxWrapper implements ResourceContext {

    private final com.yahoo.athenz.common.server.rest.ResourceContext ctx;
    private final Object timerMetric;
    private final boolean optionalAuth;
    private final String apiName;
    private final boolean eventPublishersEnabled;
    private List<DomainChangeMessage> domainChangeMessages;
    
    RsrcCtxWrapper(ServletContext servletContext, HttpServletRequest request, HttpServletResponse response,
                   Http.AuthorityList authList, boolean optionalAuth, Authorizer authorizer, Object timerMetric,
                   final String apiName, boolean eventPublishersEnabled) {
        this.optionalAuth = optionalAuth;
        this.timerMetric = timerMetric;
        this.apiName = apiName.toLowerCase();
        this.eventPublishersEnabled = eventPublishersEnabled;
        ctx = new com.yahoo.athenz.common.server.rest.ResourceContext(servletContext, request,
                response, authList, authorizer);
    }

    com.yahoo.athenz.common.server.rest.ResourceContext context() {
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
        } catch (com.yahoo.athenz.common.server.rest.ResourceException restExc) {
            throwZmsException(restExc);
        }
    }

    @Override
    public void authorize(String action, String resource, String trustedDomain) {
        try {
            ctx.authorize(action, resource, trustedDomain);
        } catch (com.yahoo.athenz.common.server.rest.ResourceException restExc) {
            logPrincipal();
            throwZmsException(restExc);
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

    void throwZmsException(com.yahoo.athenz.common.server.rest.ResourceException restExc) {

        // first check to see if this is an auth failure and if
        // that's the case include the WWW-Authenticate challenge

        ctx.sendAuthenticateChallenges(restExc);

        // now throw a ZMS exception based on the rest exception

        String msg  = null;
        Object data = restExc.getData();
        if (data instanceof String) {
            msg = (String) data;
        }
        if (msg == null) {
            msg = restExc.getMessage();
        }
        throw new com.yahoo.athenz.zms.ResourceException(restExc.getCode(),
                new ResourceError().code(restExc.getCode()).message(msg));
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
