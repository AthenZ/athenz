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
package com.yahoo.athenz.common.server.metastore.impl;

import com.yahoo.athenz.common.server.metastore.DomainMetaStore;

import java.util.ArrayList;
import java.util.List;

/**
 * Default and empty implementation for {@link DomainMetaStore}
 */
public class NoOpDomainMetaStore implements DomainMetaStore {

    @Override
    public boolean isValidBusinessService(final String domainName, final String businessService) {
        return true;
    }

    @Override
    public void setBusinessServiceDomain(final String domainName, final String businessService) {
    }

    @Override
    public List<String> getValidBusinessServices(String userName) {
        return new ArrayList<>();
    }

    @Override
    public boolean isValidAWSAccount(final String domainName, final String awsAccountId) {
        return true;
    }

    @Override
    public void setAWSAccountDomain(final String domainName, final String awsAccountId) {
    }

    @Override
    public List<String> getValidAWSAccounts(String userName) {
        return new ArrayList<>();
    }

    @Override
    public boolean isValidAzureSubscription(final String domainName, final String azureSubscription) {
        return true;
    }

    @Override
    public void setAzureSubscriptionDomain(final String domainName, final String azureSubscription) {
    }

    @Override
    public List<String> getValidAzureSubscriptions(String userName) {
        return new ArrayList<>();
    }

    @Override
    public boolean isValidGcpProject(String domainName, String gcpProject) {
        return true;
    }

    @Override
    public void setGcpProjectDomain(String domainName, String gcpProject) {
    }

    @Override
    public List<String> getValidGcpProjects(String userName) {
        return new ArrayList<>();
    }

    @Override
    public boolean isValidProductId(final String domainName, Integer productId) {
        return true;
    }

    @Override
    public void setProductIdDomain(final String domainName, Integer productId) {
    }

    @Override
    public List<String> getValidProductIds(String userName) {
        return new ArrayList<>();
    }
}
