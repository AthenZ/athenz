/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

export const LOAD_USER_DOMAINS_LIST = 'LOAD_USER_DOMAINS_LIST';
export const loadUserDomainList = (domainsList) => ({
    type: LOAD_USER_DOMAINS_LIST,
    payload: { domainsList: domainsList },
});

export const RETURN_DOMAIN_LIST = 'RETURN_DOMAIN_LIST';
export const returnDomainList = () => ({
    type: RETURN_DOMAIN_LIST,
});

export const LOAD_BUSINESS_SERVICES_ALL = 'LOAD_BUSINESS_SERVICES_ALL';
export const loadBusinessServicesAll = (businessServicesAll) => ({
    type: LOAD_BUSINESS_SERVICES_ALL,
    payload: { businessServicesAll },
});

export const RETURN_BUSINESS_SERVICES_ALL = 'RETURN_BUSINESS_SERVICES_ALL';
export const returnBusinessServicesAll = () => ({
    type: RETURN_BUSINESS_SERVICES_ALL,
});

export const RETURN_HEADER_DETAILS = 'RETURN_HEADER_DETAILS';
export const returnHeaderDetails = () => ({
    type: RETURN_HEADER_DETAILS,
});

export const LOAD_HEADER_DETAILS = 'LOAD_HEADER_DETAILS';
export const loadHeaderDetails = (headerDetails) => ({
    type: LOAD_HEADER_DETAILS,
    payload: { headerDetails: headerDetails },
});

export const RETURN_TIME_ZONE = 'RETURN_TIME_ZONE';
export const returnTimeZone = () => ({
    type: RETURN_TIME_ZONE,
});

export const LOAD_TIME_ZONE = 'LOAD_TIME_ZONE';
export const loadTimeZone = (timeZone) => ({
    type: LOAD_TIME_ZONE,
    payload: { timeZone },
});

export const RETURN_AUTHORITY_ATTRIBUTES = 'RETURN_AUTHORITY_ATTRIBUTES';
export const returnAuthorityAttributes = () => ({
    type: RETURN_AUTHORITY_ATTRIBUTES,
});

export const LOAD_AUTHORITY_ATTRIBUTES = 'LOAD_AUTHORITY_ATTRIBUTES';
export const loadAuthorityAttributes = (authorityAttributes) => ({
    type: LOAD_AUTHORITY_ATTRIBUTES,
    payload: { authorityAttributes },
});

export const RETURN_FEATURE_FLAG = 'RETURN_FEATURE_FLAG';
export const returnFeatureFlag = () => ({
    type: RETURN_FEATURE_FLAG,
});

export const LOAD_FEATURE_FLAG = 'LOAD_FEATURE_FLAG';
export const loadFeatureFlag = (featureFlag) => ({
    type: LOAD_FEATURE_FLAG,
    payload: { featureFlag },
});

export const ADD_DOMAIN_TO_USER_DOMAINS_LIST =
    'ADD_DOMAIN_TO_USER_DOMAINS_LIST';
export const addDomainToUserDomainsList = (domainName) => ({
    type: ADD_DOMAIN_TO_USER_DOMAINS_LIST,
    payload: { name: domainName, adminDomain: true },
});

export const DELETE_DOMAIN_FROM_USER_DOMAINS_LIST =
    'DELETE_DOMAIN_FROM_USER_DOMAINS_LIST';
export const deleteDomainFromUserDomainList = (subDomain) => ({
    type: DELETE_DOMAIN_FROM_USER_DOMAINS_LIST,
    payload: { subDomain },
});

export const STORE_DOMAIN_DATA = 'STORE_DOMAIN_DATA';
export const storeDomainData = (domainData) => ({
    type: STORE_DOMAIN_DATA,
    payload: { domainData: domainData },
});

export const STORE_ROLES = 'STORE_ROLES';
export const storeRoles = (rolesData) => ({
    type: STORE_ROLES,
    payload: { rolesData: rolesData },
});

export const STORE_GROUPS = 'STORE_GROUPS';
export const storeGroups = (groupsData) => ({
    type: STORE_GROUPS,
    payload: { groupsData: groupsData },
});

export const STORE_SERVICES = 'STORE_SERVICES';
export const storeServices = (servicesData) => ({
    type: STORE_SERVICES,
    payload: { servicesData: servicesData },
});

export const STORE_POLICIES = 'STORE_POLICIES';
export const storePolicies = (policiesData) => ({
    type: STORE_POLICIES,
    payload: { policiesData: policiesData },
});

export const STORE_SERVICE_DEPENDENCIES = 'STORE_SERVICE_DEPENDENCIES';
export const storeServiceDependencies = (serviceDependenciesData) => ({
    type: STORE_SERVICE_DEPENDENCIES,
    payload: { serviceDependenciesData: serviceDependenciesData },
});

export const LOAD_ALL_DOMAINS_LIST = 'LOAD_ALL_DOMAINS_LIST';
export const loadAllDomainsList = (allDomainsList) => ({
    type: LOAD_ALL_DOMAINS_LIST,
    payload: { allDomainsList },
});

export const LOAD_PENDING_DOMAIN_MEMBERS_LIST =
    'LOAD_PENDING_DOMAIN_MEMBERS_LIST';
export const loadPendingDomainMembersList = (
    pendingDomainMembersList,
    domainName
) => ({
    type: LOAD_PENDING_DOMAIN_MEMBERS_LIST,
    payload: { pendingDomainMembersList, domainName },
});

export const PROCESS_ROLE_PENDING_MEMBERS_TO_STORE =
    'PROCESS_ROLE_PENDING_MEMBERS_TO_STORE';
export const processRolePendingMembersToStore = (
    domainName,
    roleName,
    member
) => ({
    type: PROCESS_ROLE_PENDING_MEMBERS_TO_STORE,
    payload: { member, roleName, domainName },
});

export const PROCESS_GROUP_PENDING_MEMBERS_TO_STORE =
    'PROCESS_GROUP_PENDING_MEMBERS_TO_STORE';
export const processGroupPendingMembersToStore = (
    domainName,
    groupName,
    member
) => ({
    type: PROCESS_GROUP_PENDING_MEMBERS_TO_STORE,
    payload: { member, groupName, domainName },
});
