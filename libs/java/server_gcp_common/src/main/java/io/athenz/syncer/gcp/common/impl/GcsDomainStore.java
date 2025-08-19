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

package io.athenz.syncer.gcp.common.impl;

import com.google.cloud.storage.*;
import io.athenz.syncer.common.zms.CloudDomainStore;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.lang.invoke.MethodHandles;
import java.nio.charset.StandardCharsets;
import java.util.Objects;

public class GcsDomainStore implements CloudDomainStore {
    private static final Logger LOG = LoggerFactory.getLogger(MethodHandles.lookup().lookupClass());

    private final Storage storage;
    private final String projectId;
    private final String bucketName;

    public GcsDomainStore(String projectId, String bucketName) {
        this.projectId = Objects.requireNonNull(projectId);
        this.bucketName = Objects.requireNonNull(bucketName);
        this.storage = StorageOptions.newBuilder().setProjectId(projectId).build().getService();
    }

    @Override
    public void uploadDomain(final String domainName, final String domJson) {
        LOG.debug("Uploading domain: {}, under {}/{}", domainName, projectId, bucketName);
        BlobId blobId = BlobId.of(bucketName, domainName);
        BlobInfo blobInfo = BlobInfo.newBuilder(blobId).build();
        byte[] content = domJson.getBytes(StandardCharsets.UTF_8);

        storage.create(blobInfo, content);
    }

    @Override
    public void deleteDomain(final String domainName) {
        Blob blob = storage.get(bucketName, domainName);
        if (blob == null) {
            LOG.error("The object {} was not found in {}", domainName, bucketName);
            return;
        }

        storage.delete(blob.getBlobId());
    }
}
