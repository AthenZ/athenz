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

public class IdTokenCacheEntry {

    private final String idToken;
    private final long expiryTime;

    IdTokenCacheEntry(final String token, long expiryTime) {
        this.idToken = token;
        this.expiryTime = expiryTime;
    }

    public boolean isExpired(long expirySeconds) {

        // before returning our cache hit we need to make sure it
        // was at least 1/4th time left before the token expires
        // if the expiryTime is -1 then we return the token as
        // long as it's not expired

        long now = System.currentTimeMillis() / 1000;
        if (expirySeconds == -1) {
            return expiryTime <= now;
        }

        return (expiryTime < System.currentTimeMillis() / 1000 + expirySeconds / 4);
    }

    public String getIdToken() {
        return idToken;
    }
}
