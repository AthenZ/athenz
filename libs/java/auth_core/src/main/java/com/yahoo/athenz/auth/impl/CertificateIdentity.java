/*
 * Copyright 2020 Yahoo Inc.
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

    private String domain = null;
    private String service = null;
    private List<String> roles = null;
    private X509Certificate x509Certificate = null;

    /**
     * @param  domain          domain
     * @param  service         service
     * @param  roles           list of roles
     * @param  x509Certificate x509Certificate
     */
    public CertificateIdentity(String domain, String service, List<String> roles, X509Certificate x509Certificate) {
        this.domain = domain;
        this.service = service;
        this.roles = roles;
        this.x509Certificate = x509Certificate;
    }

    public String getPrincipalName() {
        return AthenzUtils.getPrincipalName(this.domain, this.service);
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
        return "{" +
            "domain:\"" + getDomain() + "\"" +
            ", service:\"" + getService() + "\"" +
            ", roles:[" + getRoles().stream().map(r -> '"' + r + '"').collect(Collectors.joining(", ")) + "]" +
            ", x509Cert:\"" + getX509Certificate().toString() + "\"" +
            "}";
    }

}
