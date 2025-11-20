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

public class TokenConfigOptions {

    KeyStore publicKeyProvider = null;
    String oauth2Issuer = null;
    ConfigurableJWTProcessor<SecurityContext> jwtIDTProcessor = null;
    ConfigurableJWTProcessor<SecurityContext> jwtJAGProcessor = null;

    public KeyStore getPublicKeyProvider() {
        return publicKeyProvider;
    }

    public void setPublicKeyProvider(KeyStore publicKeyProvider) {
        this.publicKeyProvider = publicKeyProvider;
    }

    public String getOauth2Issuer() {
        return oauth2Issuer;
    }

    public void setOauth2Issuer(String oauth2Issuer) {
        this.oauth2Issuer = oauth2Issuer;
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
