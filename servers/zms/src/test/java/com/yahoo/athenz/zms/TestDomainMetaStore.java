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
package com.yahoo.athenz.zms;

import com.yahoo.athenz.common.server.metastore.DomainMetaStore;
import com.yahoo.athenz.common.server.ServerResourceException;

import java.util.ArrayList;
import java.util.List;

public class TestDomainMetaStore implements DomainMetaStore {

    @Override
    public boolean isValidBusinessService(String domainName, String businessService) {
        return isValidAttribute(businessService);
    }

    @Override
    public void setBusinessServiceDomain(String domainName, String businessService) throws ServerResourceException {
        setAttribute(businessService);
    }

    @Override
    public List<String> getValidBusinessServices(String userName) {
        return new ArrayList<>();
    }

    @Override
    public boolean isValidAWSAccount(String domainName, String awsAccountId) {
        return isValidAttribute(awsAccountId);
    }

    @Override
    public void setAWSAccountDomain(String domainName, String awsAccountId) throws ServerResourceException {
        setAttribute(awsAccountId);
    }

    @Override
    public List<String> getValidAWSAccounts(String userName) {
        return new ArrayList<>();
    }

    @Override
    public boolean isValidAzureSubscription(String domainName, String azureSubscription) {
        return isValidAttribute(azureSubscription);
    }

    @Override
    public void setAzureSubscriptionDomain(String domainName, String azureSubscription) throws ServerResourceException {
        setAttribute(azureSubscription);
    }

    @Override
    public List<String> getValidAzureSubscriptions(String userName) {
        return new ArrayList<>();
    }

    @Override
    public boolean isValidGcpProject(String domainName, String gcpProject) {
        return isValidAttribute(gcpProject);
    }

    @Override
    public void setGcpProjectDomain(String domainName, String gcpProject) throws ServerResourceException {
        setAttribute(gcpProject);
    }

    @Override
    public List<String> getValidGcpProjects(String userName) {
        return new ArrayList<>();
    }

    @Override
    public boolean isValidProductId(String domainName, Integer productId) {
        return isValidAttribute(productId);
    }

    @Override
    public void setProductIdDomain(String domainName, Integer productId) throws ServerResourceException {
        setAttribute(productId);
    }

    @Override
    public boolean isValidProductId(String domainName, String productId) {
        return isValidAttribute(productId);
    }

    @Override
    public void setProductIdDomain(String domainName, String productId) throws ServerResourceException {
        setAttribute(productId);
    }

    @Override
    public List<String> getValidProductIds(String userName) {
        return new ArrayList<>();
    }

    private boolean isValidAttribute(String value) {
        return !(value != null && value.startsWith("invalid-"));
    }

    private boolean isValidAttribute(Integer value) {
        return value == null || value != 100;
    }

    private void setAttribute(String value) throws ServerResourceException {
        if (value != null && value.startsWith("exc-")) {
            throw new ServerResourceException(400, "Invalid value");
        }
    }

    private void setAttribute(Integer value) throws ServerResourceException {
        if (value != null && value == 99) {
            throw new ServerResourceException(400, "Invalid value");
        }
    }
}
