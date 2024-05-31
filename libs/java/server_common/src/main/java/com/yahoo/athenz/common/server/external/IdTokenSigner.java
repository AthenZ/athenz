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
package com.yahoo.athenz.common.server.external;

import com.yahoo.athenz.auth.token.IdToken;

public interface IdTokenSigner {

    /**
     * Sign the given id token and return the signed token
     * @param idToken id token to be signed
     * @param keyType key type to be used for signing: rsa or ec
     * @return signed token
     */
    String sign(IdToken idToken, String keyType);

}
