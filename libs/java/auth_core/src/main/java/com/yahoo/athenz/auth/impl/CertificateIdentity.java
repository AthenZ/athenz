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
package com.yahoo.athenz.auth.impl;

import java.security.cert.X509Certificate;
import java.util.List;
import java.util.stream.Collectors;
import com.yahoo.athenz.auth.util.AthenzUtils;

/**
 * Athenz identity from certificate
 */
public class CertificateIdentity {

    private String domain;
    private String service;
    private List<String> roles;
    private String rolePrincipalName;
    private X509Certificate x509Certificate;

    /**
     * @param domain principal's domain
     * @param service principal's service
     * @param roles list of roles, only present for role certificates
     * @param x509Certificate x509Certificate
     */
    public CertificateIdentity(final String domain, final String service, List<String> roles, X509Certificate x509Certificate) {
        setAttributes(domain, service, roles, null, x509Certificate);
    }

    /**
     * @param domain principal's domain
     * @param service principal's service
     * @param roles list of roles, only present for role certificates
     * @param rolePrincipalName role principal, only present for role certificates
     * @param x509Certificate x509Certificate
     */
    public CertificateIdentity(final String domain, final String service, List<String> roles, final String rolePrincipalName, X509Certificate x509Certificate) {
        setAttributes(domain, service, roles, rolePrincipalName, x509Certificate);
    }

    void setAttributes(final String domain, final String service, List<String> roles, final String rolePrincipalName, X509Certificate x509Certificate) {
        this.domain = domain;
        this.service = service;
        this.roles = roles;
        this.x509Certificate = x509Certificate;
        this.rolePrincipalName = rolePrincipalName;
    }

    public String getPrincipalName() {
        return AthenzUtils.getPrincipalName(this.domain, this.service);
    }

    public String getRolePrincipalName() {
        return this.rolePrincipalName;
    }

    public String getDomain() {
        return this.domain;
    }

    public String getService() {
        return this.service;
    }

    public List<String> getRoles() {
        return this.roles;
    }

    public X509Certificate getX509Certificate() {
        return this.x509Certificate;
    }

    @Override
    public String toString() {
        String data = "{" + "\"domain\":\"" + domain + "\"" + ", \"service\":\"" + service + "\"";
        if (roles != null) {
            data += ", \"roles\":[" + roles.stream().map(r -> '"' + r + '"').collect(Collectors.joining(", ")) + "]";
            data += ", \"rolePrincipalName\":\"" + rolePrincipalName + "\"";
        }
        data += ", \"x509Cert\":\"" + getX509Certificate().toString() + "\"}";
        return data;
    }

}
