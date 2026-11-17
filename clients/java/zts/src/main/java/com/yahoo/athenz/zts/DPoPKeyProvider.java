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

import java.security.KeyPair;

/**
 * Supplies the key pair used to sign DPoP proofs (RFC 9449). The provider is
 * called for every token request so implementations may rotate keys. Access
 * tokens are cached per key thumbprint, so a rotated key results in new tokens.
 */
@FunctionalInterface
public interface DPoPKeyProvider {

    /**
     * @return the current DPoP key pair or null to send requests without a DPoP proof
     */
    KeyPair getKeyPair();
}
