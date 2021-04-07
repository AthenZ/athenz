/*
 *  Copyright Athenz Authors
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
package com.yahoo.athenz.common.server.metastore;

/**
 * An interface that allows the server to verify and update domain's
 * meta attributes in some external store
 */
public interface DomainMetaStore {

    // bit sets identifying meta attributes

    int META_ATTR_BUSINESS_SERVICE    = 0;
    int META_ATTR_AWS_ACCOUNT         = 1;
    int META_ATTR_AZURE_SUBSCRIPTION  = 2;
    int META_ATTR_PRODUCT_ID          = 3;

    /**
     * Validate if the given business service is valid for the domain.
     * @param domainName - name of the domain
     * @param businessService - name of the business service (can be null)
     * @return true if valid, false otherwise
     */
    boolean isValidBusinessService(final String domainName, final String businessService);

    /**
     * Sets the athenz domain for the given business service. This attribute
     * is a regular domain meta attribute and can be changed by domain administrators.
     * @param domainName - name of the domain
     * @param businessService - name of the business service
     * @throws com.yahoo.athenz.common.server.rest.ResourceException in case of any failure
     */
    void setBusinessServiceDomain(final String domainName, final String businessService);

    /**
     * Validate if the given AWS account number is valid for the domain
     * @param domainName - name of the domain
     * @param awsAccountId - aws account id (can be null)
     * @return true if valid, false otherwise
     */
    boolean isValidAWSAccount(final String domainName, final String awsAccountId);

    /**
     * Sets the athenz domain for the aws account id. This attribute is a domain system
     * meta attribute can only be changed by athenz system administrators.
     * @param domainName - name of the domain
     * @param awsAccountId - aws account id (can be null)
     * @throws com.yahoo.athenz.common.server.rest.ResourceException in case of any failure
     */
    void setAWSAccountDomain(final String domainName, final String awsAccountId);

    /**
     * Validate if the given Azure subscription id is valid for the domain
     * @param domainName - name of the domain
     * @param azureSubscription - azure subscription id (can be null)
     * @return true if valid, false otherwise
     */
    boolean isValidAzureSubscription(final String domainName, final String azureSubscription);

    /**
     * Sets the athenz domain for the azure subscription. This attribute is a domain
     * system meta attribute can only be changed by athenz system administrators.
     * @param domainName - name of the domain
     * @param azureSubscription - azure subscription id (can be null)
     * @throws com.yahoo.athenz.common.server.rest.ResourceException in case of any failure
     */
    void setAzureSubscriptionDomain(final String domainName, final String azureSubscription);

    /**
     * Validate if the given product id is valid for the domain
     * @param domainName - name of the domain
     * @param productId - product id (can be null)
     * @return true if valid, false otherwise
     */
    boolean isValidProductId(final String domainName, Integer productId);

    /**
     * Sets the athenz domain for the given product id. This attribute is a domain
     * system meta attribute can only be changed by athenz system administrators.
     * @param domainName - name of the domain
     * @param productId - product id (can be null)
     * @throws com.yahoo.athenz.common.server.rest.ResourceException in case of any failure
     */
    void setProductIdDomain(final String domainName, Integer productId);
}
