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
package io.athenz.syncer.common.zms.impl;

import io.athenz.syncer.common.zms.CloudDomainStore;

public class CloudDomainStoreNoOp implements CloudDomainStore {
    @Override
    public void uploadDomain(final String domainName, final String domJson) {
        // No-op
    }

    @Override
    public void deleteDomain(final String domainName) {
        // No-op
    }
}
