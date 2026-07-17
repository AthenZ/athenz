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
package io.athenz.server.aws.common.store.impl;

import software.amazon.awssdk.regions.Region;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Test double for AWSObjectStoreFactory that stubs region-scoped token generation and
 * connection verification, so getAuthTokenFromCandidateRegions() candidate-region cycling
 * can be exercised without real AWS/database calls.
 */
class CandidateRegionTestFactory extends AWSObjectStoreFactory {

    private Region workingRegion;
    private Region noTokenRegion;
    final List<Region> regionsTried = new CopyOnWriteArrayList<>();

    CandidateRegionTestFactory(Region workingRegion) {
        this.workingRegion = workingRegion;
    }

    void setWorkingRegion(Region workingRegion) {
        this.workingRegion = workingRegion;
    }

    void setNoTokenRegion(Region noTokenRegion) {
        this.noTokenRegion = noTokenRegion;
    }

    @Override
    Region getRegion() {
        return Region.US_EAST_1;
    }

    @Override
    String getAuthToken(String hostname, int port, String rdsUser, Region region) {
        regionsTried.add(region);
        if (region.equals(noTokenRegion)) {
            return null;
        }
        return "token-" + region.id();
    }

    @Override
    boolean verifyConnection(String jdbcUrl, String rdsUser, String token) {
        return token.equals("token-" + workingRegion.id());
    }
}
