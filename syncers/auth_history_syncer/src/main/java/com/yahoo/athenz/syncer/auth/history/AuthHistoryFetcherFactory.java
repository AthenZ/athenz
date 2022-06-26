/*
 *
 *  * Copyright The Athenz Authors
 *  *
 *  * Licensed under the Apache License, Version 2.0 (the "License");
 *  * you may not use this file except in compliance with the License.
 *  * You may obtain a copy of the License at
 *  *
 *  *     http://www.apache.org/licenses/LICENSE-2.0
 *  *
 *  * Unless required by applicable law or agreed to in writing, software
 *  * distributed under the License is distributed on an "AS IS" BASIS,
 *  * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  * See the License for the specific language governing permissions and
 *  * limitations under the License.
 *
 */

package com.yahoo.athenz.syncer.auth.history;

import com.yahoo.athenz.auth.PrivateKeyStore;

public interface AuthHistoryFetcherFactory {
    /**
     * Create AuthHistoryFetcher
     * @param pkeyStore - key store to be used for retrieving secrets / certificates
     * @param region - region (only for AWS case)
     * @return AuthHistoryFetcher instance
     */
    AuthHistoryFetcher create(PrivateKeyStore pkeyStore, String region);
}
