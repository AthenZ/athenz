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

public class AccessTokenResponseCacheEntry {

    private AccessTokenResponse accessTokenResponse;
    long expiryTime;
    long serverExpirySecs;

    AccessTokenResponseCacheEntry(AccessTokenResponse accessTokenResponse) {
        this.accessTokenResponse = accessTokenResponse;
        this.expiryTime = System.currentTimeMillis() / 1000 + accessTokenResponse.getExpires_in();
        this.serverExpirySecs = accessTokenResponse.getExpires_in();
    }

    public boolean isExpired(long expirySeconds) {

        // before returning our cache hit we need to make sure it
        // it was at least 1/4th time left before the token expires
        // if the expiryTime is -1 then we return the token as
        // long as its not expired

        long now = System.currentTimeMillis() / 1000;
        if (expirySeconds == -1) {
            return expiryTime <= now;
        }

        // if we have no expiry seconds specified, then we're going
        // to use the original server expiry seconds specified in
        // the token response object

        if (expirySeconds == 0) {
            expirySeconds = serverExpirySecs;
        }
        return (expiryTime < System.currentTimeMillis() / 1000 + expirySeconds / 4);
    }

    public AccessTokenResponse accessTokenResponse() {
        AccessTokenResponse tokenResponse = new AccessTokenResponse();
        tokenResponse.setAccess_token(accessTokenResponse.getAccess_token());
        tokenResponse.setId_token(accessTokenResponse.getId_token());
        tokenResponse.setToken_type(accessTokenResponse.getToken_type());
        tokenResponse.setRefresh_token(accessTokenResponse.getRefresh_token());
        tokenResponse.setScope(accessTokenResponse.getScope());
        tokenResponse.setExpires_in((int) (expiryTime - System.currentTimeMillis() / 1000));
        return tokenResponse;
    }
}
