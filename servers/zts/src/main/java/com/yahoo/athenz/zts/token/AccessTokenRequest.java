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
package com.yahoo.athenz.zts.token;

import com.yahoo.athenz.zts.ZTSConsts;
import org.eclipse.jetty.util.StringUtil;

public class AccessTokenRequest extends OAuthTokenRequest {

    private static boolean supportOpenIdScope = Boolean.parseBoolean(
            System.getProperty(ZTSConsts.ZTS_PROP_OAUTH_OPENID_SCOPE, "false"));

    public AccessTokenRequest(final String scope) {

        // the format of our scopes for role access token and id tokens are:
        // access token/id token combo:
        //   <domainName>:domain
        //   <domainName>:role.<roleName>
        //   openid <domainName>:service.<serviceName>

        super(scope, 1);

        // if we don't have a domain then it's invalid scope

        if (StringUtil.isEmpty(getDomainName())) {
            throw error("No domains in scope", scope);
        }

        // for openid scope we must have the openid scope
        // along with the service name since the audience
        // must be set for that service only

        if (openIdScope && StringUtil.isEmpty(serviceName)) {
            throw error("No audience service name for openid scope", scope);
        }
    }

    @Override
    public boolean isOpenIdScope() {
        return supportOpenIdScope && openIdScope;
    }

    public static void setSupportOpenIdScope(boolean value) {
        supportOpenIdScope = value;
    }
}
