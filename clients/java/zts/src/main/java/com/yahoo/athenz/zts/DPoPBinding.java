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

import com.yahoo.athenz.auth.token.DPoPProof;

import java.security.KeyPair;

/**
 * DPoP settings sampled once for a single token request: the key used to sign
 * the proof, to build the cache key and to verify the response all come from
 * the same snapshot.
 */
final class DPoPBinding {

    static final DPoPBinding NONE = new DPoPBinding(null, false);

    final KeyPair keyPair;
    final boolean allowBearerFallback;

    DPoPBinding(final KeyPair keyPair, boolean allowBearerFallback) {
        this.keyPair = keyPair;
        this.allowBearerFallback = allowBearerFallback;
    }

    boolean isEnabled() {
        return keyPair != null;
    }

    String getThumbprint() {
        return DPoPProof.computeJwkThumbprint(keyPair.getPublic());
    }
}
