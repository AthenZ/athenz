import {
    ADD_SUB_DOMAIN,
    ADD_USER_DOMAIN,
    DELETE_SUB_DOMAIN,
    LOAD_ALL_DOMAINS_LIST,
    LOAD_BUSINESS_SERVICES_ALL,
    LOAD_PENDING_DOMAIN_MEMBERS_LIST,
    LOAD_USER_DOMAINS_LIST,
    PROCESS_PENDING_MEMBERS_TO_STORE,
    RETURN_BUSINESS_SERVICES_ALL,
    RETURN_DOMAIN_LIST,
    STORE_DOMAIN_DATA,
    STORE_GROUPS,
    STORE_HISTORY,
    STORE_MICROSEGMENTATION,
    STORE_POLICIES,
    STORE_ROLES,
    STORE_SERVICE_DEPENDENCIES,
    STORE_SERVICES,
} from '../actions/domains';
import produce from 'immer';

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
        case ADD_SUB_DOMAIN: {
            const { name, adminDomain } = payload;
            return produce(state, (draft) => {
                draft.domainsList
                    ? draft.domainsList.concat({
                          name,
                          adminDomain,
                      })
                    : (draft.domainsList = [{ name, adminDomain }]);
            });
        }

        case ADD_USER_DOMAIN: {
            const { name, adminDomain } = payload;
            return produce(state, (draft) => {
                draft.domainsList
                    ? draft.domainsList.concat({
                          name,
                          adminDomain,
                      })
                    : (draft.domainsList = [{ name, adminDomain }]);
            });
        }
        case DELETE_SUB_DOMAIN: {
            const { subDomain } = payload;
            return produce(state, (draft) => {
                draft.domainsList.filter((domain) => domain.name !== subDomain);
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
            const { servicesData: servicesData } = payload;
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

        case STORE_HISTORY: {
            const { historyData } = payload;
            let newState = produce(state, (draft) => {
                if (draft[historyData.domainName]) {
                    draft[historyData.domainName].history = historyData;
                } else {
                    draft[historyData.domainName] = {
                        history: { ...historyData },
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

        case STORE_MICROSEGMENTATION: {
            const { microsegmentationData: microsegmentationData } = payload;
            let newState = produce(state, (draft) => {
                if (draft[microsegmentationData.domainName]) {
                    draft[
                        microsegmentationData.domainName
                    ].microsegmentationData = microsegmentationData;
                } else {
                    draft[microsegmentationData.domainName] = {
                        microsegmentationData: { ...microsegmentationData },
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
                    draft[domainName].domainData.pendingDomainMembersList =
                        pendingDomainMembersList;
                } else {
                    draft[domainName] = {
                        domainData: {
                            pendingDomainMembersList: {
                                ...pendingDomainMembersList,
                            },
                        },
                    };
                }
            });
            return newState;
        }
        case PROCESS_PENDING_MEMBERS_TO_STORE: {
            const { member, domainName, roleName } = payload;
            let newState = produce(state, (draft) => {
                if (draft[domainName]) {
                    delete draft[domainName].domainData
                        .pendingDomainMembersList[
                        domainName + member.memberName + roleName
                    ];
                }
            });
            return newState;
        }
        case RETURN_BUSINESS_SERVICES_ALL:
        case RETURN_DOMAIN_LIST:
        default:
            return state;
    }
};
