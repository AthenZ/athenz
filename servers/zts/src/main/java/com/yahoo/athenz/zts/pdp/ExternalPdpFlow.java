/*
 *  Copyright The Athenz Authors
 *
 *  Licensed under the Apache License, Version 2.0 (the "License");
 *  you may not use this file except in compliance with the License.
 *  You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 *  Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

package com.yahoo.athenz.zts.pdp;

import com.yahoo.athenz.zts.token.AccessTokenRequest.RequestType;

/**
 * OAuth2 token flows that can be routed through the external PDP.
 */
public enum ExternalPdpFlow {

    ACCESS_TOKEN("access_token"),
    TOKEN_EXCHANGE("token_exchange"),
    JAG("jag");

    private final String configName;

    ExternalPdpFlow(final String configName) {
        this.configName = configName;
    }

    public String getConfigName() {
        return configName;
    }

    /**
     * @param configName flow name as used in the configuration property
     * @return the matching flow or null if unknown
     */
    public static ExternalPdpFlow fromConfigName(final String configName) {
        for (ExternalPdpFlow flow : values()) {
            if (flow.configName.equals(configName)) {
                return flow;
            }
        }
        return null;
    }

    /**
     * @param requestType token request type
     * @return the flow for the request type, or null if the request type is not PDP-eligible
     */
    public static ExternalPdpFlow fromRequestType(final RequestType requestType) {
        switch (requestType) {
            case ACCESS_TOKEN:
                return ACCESS_TOKEN;
            case ACCESS_TOKEN_EXCHANGE:
                return TOKEN_EXCHANGE;
            case JAG_TOKEN_EXCHANGE:
            case JAG_JWT_BEARER:
                return JAG;
            default:
                return null;
        }
    }
}
