/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.common.server.notification.impl;

import com.yahoo.athenz.auth.Authority;
import com.yahoo.athenz.auth.Principal;

import jakarta.servlet.http.HttpServletRequest;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.EnumSet;
import java.util.List;
import java.util.Set;

public class NotificationAuthorityForTest implements Authority {
    @Override
    public void initialize() {

    }

    @Override
    public String getID() {
        return null;
    }

    @Override
    public CredSource getCredSource() {
        return null;
    }

    @Override
    public String getDomain() {
        return null;
    }

    @Override
    public String getHeader() {
        return null;
    }

    @Override
    public String getAuthenticateChallenge() {
        return null;
    }

    @Override
    public boolean allowAuthorization() {
        return false;
    }

    @Override
    public String getUserDomainName(String userName) {
        return null;
    }

    @Override
    public boolean isValidUser(String username) {
        return false;
    }

    @Override
    public Principal authenticate(String creds, String remoteAddr, String httpMethod, StringBuilder errMsg) {
        return null;
    }

    @Override
    public Principal authenticate(X509Certificate[] certs, StringBuilder errMsg) {
        return null;
    }

    @Override
    public Principal authenticate(HttpServletRequest request, StringBuilder errMsg) {
        return null;
    }

    @Override
    public boolean isAttributeSet(String username, String attribute) {
        return false;
    }

    @Override
    public Set<String> booleanAttributesSupported() {
        return null;
    }

    @Override
    public Date getDateAttribute(String username, String attribute) {
        return null;
    }

    @Override
    public Set<String> dateAttributesSupported() {
        return null;
    }

    @Override
    public String getUserEmail(String username) {
        if (username.equals("unknown.user")) {
            return null;
        }
        return username + "@mail.from.authority.com";
    }

    @Override
    public List<Principal> getPrincipals(EnumSet<Principal.State> principalStates) {
        return null;
    }
}
