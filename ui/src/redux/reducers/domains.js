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

import {
    ADD_DOMAIN_TO_USER_DOMAINS_LIST,
    DELETE_DOMAIN_FROM_USER_DOMAINS_LIST,
    LOAD_ALL_DOMAINS_LIST,
    LOAD_AUTHORITY_ATTRIBUTES,
    LOAD_BUSINESS_SERVICES_ALL,
    LOAD_FEATURE_FLAG,
    LOAD_HEADER_DETAILS,
    LOAD_TIME_ZONE,
    LOAD_PENDING_DOMAIN_MEMBERS_LIST,
    LOAD_USER_DOMAINS_LIST,
    PROCESS_GROUP_PENDING_MEMBERS_TO_STORE,
    PROCESS_ROLE_PENDING_MEMBERS_TO_STORE,
    RETURN_AUTHORITY_ATTRIBUTES,
    RETURN_BUSINESS_SERVICES_ALL,
    RETURN_DOMAIN_LIST,
    RETURN_FEATURE_FLAG,
    RETURN_HEADER_DETAILS,
    RETURN_TIME_ZONE,
    STORE_DOMAIN_DATA,
    STORE_GROUPS,
    STORE_POLICIES,
    STORE_ROLES,
    STORE_SERVICE_DEPENDENCIES,
    STORE_SERVICES,
} from '../actions/domains';
import produce from 'immer';
import { UPDATE_BELL_PENDING_MEMBERS } from '../actions/domain-data';

export const domains = (state = {}, action) => {
    const { type, payload } = action;
    switch (type) {
        case LOAD_USER_DOMAINS_LIST: {
            const { domainsList } = payload;
            let newState = produce(state, (draft) => {
                draft.domainsList = domainsList;
            });
            return newState;
        }
        case LOAD_BUSINESS_SERVICES_ALL: {
            const { businessServicesAll } = payload;
            let newState = produce(state, (draft) => {
                draft.businessServicesAll = businessServicesAll;
            });
            return newState;
        }
        case ADD_DOMAIN_TO_USER_DOMAINS_LIST: {
            const { name, adminDomain } = payload;
            let newState = produce(state, (draft) => {
                draft.domainsList
                    ? draft.domainsList.push({ name, adminDomain })
                    : (draft.domainsList = [{ name, adminDomain }]);
            });
            return newState;
        }
        case DELETE_DOMAIN_FROM_USER_DOMAINS_LIST: {
            const { domainName } = payload;
            return produce(state, (draft) => {
                draft.domainsList = draft.domainsList.filter(
                    (domain) => domain.name !== domainName
                );
            });
        }
        case STORE_ROLES: {
            const { rolesData } = payload;
            let newState = produce(state, (draft) => {
                if (draft[rolesData.domainName]) {
                    draft[rolesData.domainName].roles = rolesData;
                } else {
                    draft[rolesData.domainName] = { roles: { ...rolesData } };
                }
            });

            return newState;
        }
        case STORE_DOMAIN_DATA: {
            const { domainData } = payload;
            let newState = produce(state, (draft) => {
                if (draft[domainData.domainName]) {
                    draft[domainData.domainName].domainData = domainData;
                } else {
                    draft[domainData.domainName] = {
                        domainData: { ...domainData },
                    };
                }
            });
            return newState;
        }
        case STORE_GROUPS: {
            const { groupsData: groupsData } = payload;
            const newState = produce(state, (draft) => {
                if (draft[groupsData.domainName]) {
                    draft[groupsData.domainName].groups = groupsData;
                } else {
                    draft[groupsData.domainName] = {
                        groups: { ...groupsData },
                    };
                }
            });
            return newState;
        }
        case STORE_SERVICES: {
            const { servicesData } = payload;
            let newState = produce(state, (draft) => {
                if (draft[servicesData.domainName]) {
                    draft[servicesData.domainName].services = servicesData;
                } else {
                    draft[servicesData.domainName] = {
                        services: { ...servicesData },
                    };
                }
            });
            return newState;
        }
        case STORE_POLICIES: {
            const { policiesData: policiesData } = payload;
            let newState = produce(state, (draft) => {
                if (draft[policiesData.domainName]) {
                    draft[policiesData.domainName].policies = policiesData;
                } else {
                    draft[policiesData.domainName] = {
                        policies: { ...policiesData },
                    };
                }
            });

            return newState;
        }
        case STORE_SERVICE_DEPENDENCIES: {
            const { serviceDependenciesData } = payload;
            let newState = produce(state, (draft) => {
                if (draft[serviceDependenciesData.domainName]) {
                    draft[
                        serviceDependenciesData.domainName
                    ].serviceDependenciesData = serviceDependenciesData;
                } else {
                    draft[serviceDependenciesData.domainName] = {
                        serviceDependenciesData: { ...serviceDependenciesData },
                    };
                }
            });
            return newState;
        }
        case LOAD_ALL_DOMAINS_LIST: {
            const { allDomainsList } = payload;
            let newState = produce(state, (draft) => {
                draft.allDomainsList = allDomainsList;
            });
            return newState;
        }
        case LOAD_PENDING_DOMAIN_MEMBERS_LIST: {
            const { pendingDomainMembersList, domainName } = payload;
            let newState = produce(state, (draft) => {
                if (draft[domainName]) {
                    draft[domainName].domainData.pendingMembersList =
                        pendingDomainMembersList;
                } else {
                    draft[domainName] = {
                        domainData: {
                            pendingMembersList: pendingDomainMembersList,
                        },
                    };
                }
            });
            return newState;
        }
        case PROCESS_ROLE_PENDING_MEMBERS_TO_STORE: {
            const { member, domainName, roleName } = payload;
            let newState = produce(state, (draft) => {
                if (draft[domainName]) {
                    delete draft[domainName].domainData.pendingMembersList[
                        domainName + member.memberName + roleName
                    ];
                }
            });
            return newState;
        }
        case PROCESS_GROUP_PENDING_MEMBERS_TO_STORE: {
            const { member, domainName, groupName } = payload;
            let newState = produce(state, (draft) => {
                if (draft[domainName]) {
                    delete draft[domainName].domainData.pendingMembersList[
                        domainName + member.memberName + groupName
                    ];
                }
            });
            return newState;
        }
        /**
         * if you someone tries to reject or approve a pending member from the
         * workflow pages admin/domain and the domain already loaded into the store,
         * so it needs to update the bell pending member as well
         */
        case UPDATE_BELL_PENDING_MEMBERS: {
            const { memberName, collection } = payload;
            let domainName = collection.split(':')[0];
            let newState = produce(state, (draft) => {
                if (draft[domainName]) {
                    if (draft[domainName].domainData.bellPendingMembers) {
                        if (
                            draft[domainName].domainData.bellPendingMembers[
                                collection + memberName
                            ]
                        ) {
                            delete draft[domainName].domainData
                                .bellPendingMembers[collection + memberName];
                        } else {
                            draft[domainName].domainData.bellPendingMembers[
                                collection + memberName
                            ] = true;
                        }
                    } else {
                        draft[domainName].domainData.bellPendingMembers = {
                            [collection + memberName]: true,
                        };
                    }
                }
            });
            return newState;
        }
        case LOAD_HEADER_DETAILS: {
            const { headerDetails } = payload;
            let newState = produce(state, (draft) => {
                draft.headerDetails = headerDetails;
            });
            return newState;
        }
        case LOAD_TIME_ZONE: {
            const { timeZone } = payload;
            let newState = produce(state, (draft) => {
                draft.timeZone = timeZone;
            });
            return newState;
        }
        case LOAD_AUTHORITY_ATTRIBUTES: {
            const { authorityAttributes } = payload;
            let newState = produce(state, (draft) => {
                draft.authorityAttributes = authorityAttributes;
            });
            return newState;
        }
        case LOAD_FEATURE_FLAG: {
            const { featureFlag } = payload;
            let newState = produce(state, (draft) => {
                draft.featureFlag = featureFlag;
            });
            return newState;
        }
        case RETURN_AUTHORITY_ATTRIBUTES:
        case RETURN_FEATURE_FLAG:
        case RETURN_HEADER_DETAILS:
        case RETURN_TIME_ZONE:
        case RETURN_BUSINESS_SERVICES_ALL:
        case RETURN_DOMAIN_LIST:
        default:
            return state;
    }
};
