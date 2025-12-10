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

import com.nimbusds.jose.proc.SecurityContext;
import com.nimbusds.jwt.proc.ConfigurableJWTProcessor;
import com.yahoo.athenz.auth.KeyStore;

import java.util.Set;

public class TokenConfigOptions {

    KeyStore publicKeyProvider = null;
    Set<String> oauth2Issuers = null;
    ConfigurableJWTProcessor<SecurityContext> jwtIDTProcessor = null;
    ConfigurableJWTProcessor<SecurityContext> jwtJAGProcessor = null;

    public KeyStore getPublicKeyProvider() {
        return publicKeyProvider;
    }

    public void setPublicKeyProvider(KeyStore publicKeyProvider) {
        this.publicKeyProvider = publicKeyProvider;
    }

    public Set<String> getOauth2Issuers() {
        return oauth2Issuers;
    }

    public void setOauth2Issuers(Set<String> oauth2Issuers) {
        this.oauth2Issuers = oauth2Issuers;
    }

    public ConfigurableJWTProcessor<SecurityContext> getJwtIDTProcessor() {
        return jwtIDTProcessor;
    }

    public void setJwtIDTProcessor(ConfigurableJWTProcessor<SecurityContext> jwtIDTProcessor) {
        this.jwtIDTProcessor = jwtIDTProcessor;
    }

    public ConfigurableJWTProcessor<SecurityContext> getJwtJAGProcessor() {
        return jwtJAGProcessor;
    }

    public void setJwtJAGProcessor(ConfigurableJWTProcessor<SecurityContext> jwtJAGProcessor) {
        this.jwtJAGProcessor = jwtJAGProcessor;
    }
}
