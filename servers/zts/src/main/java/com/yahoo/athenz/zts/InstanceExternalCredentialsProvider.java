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

import com.yahoo.athenz.auth.Authorizer;
import com.yahoo.athenz.auth.Principal;
import com.yahoo.athenz.auth.impl.SimplePrincipal;
import com.yahoo.athenz.auth.util.AthenzUtils;
import com.yahoo.athenz.common.metrics.Metric;
import com.yahoo.athenz.common.server.rest.Http;
import com.yahoo.athenz.instance.provider.ExternalCredentialsProvider;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

public class InstanceExternalCredentialsProvider implements ExternalCredentialsProvider {

    private final String providerDomainName;
    private final String providerServiceName;
    private final ZTSHandler ztsHandler;

    public InstanceExternalCredentialsProvider(final String providerName, final ZTSHandler ztsHandler) {
        this.providerDomainName = AthenzUtils.extractPrincipalDomainName(providerName);
        this.providerServiceName = AthenzUtils.extractPrincipalServiceName(providerName);
        this.ztsHandler = ztsHandler;
    }

    @Override
    public ExternalCredentialsResponse getExternalCredentials(String provider, String domainName,
            ExternalCredentialsRequest extCredsRequest) {

        Principal principal = SimplePrincipal.create(providerDomainName, providerServiceName, (String) null);
        ProviderResourceContext ctx = new ProviderResourceContext(null, null, null, null, false,
                null, null, null, "getexternalcredentials");
        ctx.setPrincipal(principal);
        return ztsHandler.postExternalCredentialsRequest(ctx, provider, domainName, extCredsRequest);
    }

    static class ProviderResourceContext extends RsrcCtxWrapper {

        Principal principal = null;

        public ProviderResourceContext(ServletContext servletContext, HttpServletRequest request,
                HttpServletResponse response, Http.AuthorityList authList, boolean optionalAuth,
                Authorizer authorizer, Metric metric, Object timerMetric, String apiName) {
            super(servletContext, request, response, authList, optionalAuth, authorizer, metric, timerMetric, apiName);
        }

        public void setPrincipal(Principal principal) {
            this.principal = principal;
        }

        @Override
        public Principal principal() {
            return principal;
        }
    }
}
