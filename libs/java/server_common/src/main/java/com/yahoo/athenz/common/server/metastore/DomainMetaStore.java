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
package com.yahoo.athenz.common.server.metastore;

import com.yahoo.athenz.common.server.ServerResourceException;

import java.util.List;

/**
 * An interface that allows the server to verify and update domain's
 * meta attributes in some external store
 */
public interface DomainMetaStore {

    // bit sets identifying meta attributes

    int META_ATTR_BUSINESS_SERVICE    = 0;
    int META_ATTR_AWS_ACCOUNT         = 1;
    int META_ATTR_AZURE_SUBSCRIPTION  = 2;
    int META_ATTR_PRODUCT_NUMBER      = 3;
    int META_ATTR_GCP_PROJECT         = 4;
    int META_ATTR_PRODUCT_ID          = 5;
    int META_ATTR_ON_CALL             = 6;

    // valid attribute names

    String META_ATTR_BUSINESS_SERVICE_NAME = "businessService";
    String META_ATTR_AWS_ACCOUNT_NAME = "awsAccount";
    String META_ATTR_AZURE_SUBSCRIPTION_NAME = "azureSubscription";
    String META_ATTR_GCP_PROJECT_NAME = "gcpProject";
    String META_ATTR_PRODUCT_NUMBER_NAME = "productNumber";
    String META_ATTR_PRODUCT_ID_NAME = "productId";
    String META_ATTR_ON_CALL_NAME = "onCall";

    /**
     * Validate if the given business service is valid for the domain.
     * @param domainName - name of the domain
     * @param businessService - name of the business service (can be null)
     * @return true if valid, false otherwise
     */
    boolean isValidBusinessService(final String domainName, final String businessService) throws ServerResourceException;

    /**
     * Sets the athenz domain for the given business service. This attribute
     * is a regular domain meta attribute and can be changed by domain administrators.
     * @param domainName - name of the domain
     * @param businessService - name of the business service
     * @throws ServerResourceException in case of any failure
     */
    void setBusinessServiceDomain(final String domainName, final String businessService) throws ServerResourceException;

    /**
     * Get a list of valid business services
     * @param userName (optional) if not null, only get business services associated with the user
     * @return Business Services List
     */
    List<String> getValidBusinessServices(final String userName)throws ServerResourceException;

    /**
     * Validate if the given AWS account number is valid for the domain
     * @param domainName - name of the domain
     * @param awsAccountId - aws account id (can be null)
     * @return true if valid, false otherwise
     */
    boolean isValidAWSAccount(final String domainName, final String awsAccountId) throws ServerResourceException;

    /**
     * Sets the athenz domain for the aws account id. This attribute is a domain system
     * meta attribute can only be changed by athenz system administrators.
     * @param domainName - name of the domain
     * @param awsAccountId - aws account id (can be null)
     * @throws ServerResourceException in case of any failure
     */
    void setAWSAccountDomain(final String domainName, final String awsAccountId) throws ServerResourceException;

    /**
     * Get a list of valid AWS Accounts
     * @param userName (optional) if not null, only get AWS accounts associated with the user
     * @return AWS Accounts List
     */
    List<String> getValidAWSAccounts(final String userName) throws ServerResourceException;

    /**
     * Validate if the given Azure subscription id is valid for the domain
     * @param domainName - name of the domain
     * @param azureSubscription - azure subscription id (can be null)
     * @return true if valid, false otherwise
     */
    boolean isValidAzureSubscription(final String domainName, final String azureSubscription) throws ServerResourceException;

    /**
     * Sets the athenz domain for the azure subscription. This attribute is a domain
     * system meta attribute can only be changed by athenz system administrators.
     * @param domainName - name of the domain
     * @param azureSubscription - azure subscription id (can be null)
     * @throws ServerResourceException in case of any failure
     */
    void setAzureSubscriptionDomain(final String domainName, final String azureSubscription) throws ServerResourceException;

    /**
     * Get a list of valid Azure Subscriptions
     * @param userName (optional) if not null, only get Azure subscriptions associated with the user
     * @return Azure Subscriptions List
     */
    List<String> getValidAzureSubscriptions(final String userName) throws ServerResourceException;

    /**
     * Validate if the given GCP project name is valid for the domain
     * @param domainName - name of the domain
     * @param gcpProject - gcp project (can be null)
     * @return true if valid, false otherwise
     */
    boolean isValidGcpProject(final String domainName, final String gcpProject) throws ServerResourceException;

    /**
     * Sets the athenz domain for the gcp project. This attribute is a domain
     * system meta attribute can only be changed by athenz system administrators.
     * @param domainName - name of the domain
     * @param gcpProject - gcp project (can be null)
     * @throws ServerResourceException in case of any failure
     */
    void setGcpProjectDomain(final String domainName, final String gcpProject) throws ServerResourceException;

    /**
     * Get a list of valid GCP Projects
     * @param userName (optional) if not null, only get GCP Projects associated with the user
     * @return GCP Project List
     */
    List<String> getValidGcpProjects(final String userName) throws ServerResourceException;

    /**
     * Validate if the given product id is valid for the domain
     * @param domainName - name of the domain
     * @param productId - product id (can be null)
     * @return true if valid, false otherwise
     */
    boolean isValidProductId(final String domainName, Integer productId) throws ServerResourceException;

    /**
     * Sets the athenz domain for the given product id. This attribute is a domain
     * system meta attribute can only be changed by athenz system administrators.
     * @param domainName - name of the domain
     * @param productId - product id (can be null)
     * @throws ServerResourceException in case of any failure
     */
    void setProductIdDomain(final String domainName, Integer productId) throws ServerResourceException;

    /**
     * Validate if the given product id is valid for the domain
     * @param domainName - name of the domain
     * @param productId - product id (can be null)
     * @return true if valid, false otherwise
     */
    default boolean isValidProductId(final String domainName, String productId) throws ServerResourceException {
        return true;
    }

    /**
     * Sets the athenz domain for the given product id. This attribute is a domain
     * system meta attribute can only be changed by athenz system administrators.
     * @param domainName - name of the domain
     * @param productId - product id (can be null)
     * @throws ServerResourceException in case of any failure
     */
    default void setProductIdDomain(final String domainName, String productId) throws ServerResourceException {
    }

    /**
     * Get a list of valid Product Ids
     * @param userName (optional) if not null, only get Product ids associated with the user
     * @return Product Ids List
     */
    List<String> getValidProductIds(final String userName) throws ServerResourceException;

    /**
     * Validate if the given on-call team id/name is valid for the domain
     * @param domainName - name of the domain
     * @param onCall - on call support team id/name (can be null)
     * @return true if valid, false otherwise
     */
    default boolean isValidOnCall(final String domainName, final String onCall) throws ServerResourceException {
        return true;
    }

    /**
     * Sets the athenz domain for the given on-call team name/id. This attribute
     * is a regular domain meta attribute and can be changed by domain administrators.
     * @param domainName - name of the domain
     * @param onCall - on-call support team id/name (can be null)
     * @throws ServerResourceException in case of any failure
     */
    default void setOnCallDomain(final String domainName, final String onCall) throws ServerResourceException {
    }

    /**
     * Get a list of valid on-call support team names/ids
     * @param userName (optional) if not null, only get on-call team names/ids associated with the user
     * @return on-call team id/name List
     */
    default List<String> getValidOnCalls(final String userName) throws ServerResourceException {
        return List.of();
    }
}
