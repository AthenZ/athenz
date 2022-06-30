import {
    GET_USER_DOMAINS_LIST,
    LOAD_USER_DOMAINS_LIST,
    RETURN_DOMAIN_LIST,
    STORE_DOMAIN_DATA,
    STORE_GROUPS,
    STORE_HISTORY,
    STORE_POLICIES,
    STORE_ROLES,
    STORE_SERVICES,
} from '../actions/domains';
import { LOAD_ALL_BUSINESS_DATA } from '../actions/domain-data';

// let bServicesParamsAll = {
//     category: 'domain',
//     attributeName: 'businessService',
// };
// const headerBusinessDataAll = await api.getMeta(bServicesParamsAll);

// case LOAD_ALL_BUSINESS_DATA: {
//     const { allBusinessData } = payload;
//     let businessServiceOptionsAll = [];
//     if (allBusinessData.validValues) {
//         allBusinessData.validValues.forEach((businessService) => {
//             let bServiceOnlyId = businessService.substring(
//                 0,
//                 businessService.indexOf(':')
//             );
//             let bServiceOnlyName = businessService.substring(
//                 businessService.indexOf(':') + 1
//             );
//             businessServiceOptionsAll.push({
//                 value: bServiceOnlyId,
//                 name: bServiceOnlyName,
//             });
//         });
//         return {
//             ...state,
//             businessServiceOptionsAll: businessServiceOptionsAll,
//         };
//     }
// }

export const domains = (state = {}, action) => {
    const { type, payload } = action;
    switch (type) {
        case LOAD_USER_DOMAINS_LIST: {
            const { domainsList } = payload;
            state.domainsList = domainsList;
            return { ...state };
        }
        case STORE_ROLES: {
            const { rolesData } = payload;
            if (state[rolesData.domainName]) {
                state[rolesData.domainName].roles = rolesData;
            } else {
                state[rolesData.domainName] = { roles: { ...rolesData } };
            }
            return { ...state };
        }
        case STORE_DOMAIN_DATA: {
            const { domainData } = payload;
            if (state[domainData.name]) {
                state[domainData.name].domainData = domainData;
            } else {
                state[domainData.name] = { domainData: { ...domainData } };
            }
        }
        case STORE_GROUPS: {
            const { groupsData: groupsData } = payload;
            const newState = { ...state };
            if (state[groupsData.domainName]) {
                state[groupsData.domainName].groups = groupsData;
            } else {
                state[groupsData.domainName] = { groups: { ...groupsData } };
            }
            return { ...state };
        }
        case STORE_SERVICES: {
            const { servicesData: servicesData } = payload;
            if (state[servicesData.domainName]) {
                state[servicesData.domainName].services = servicesData;
            } else {
                state[servicesData.domainName] = {
                    services: { ...servicesData },
                };
            }
            return { ...state };
        }
        case STORE_POLICIES: {
            const { policiesData: policiesData } = payload;
            if (state[policiesData.domainName]) {
                state[policiesData.domainName].policies = policiesData;
            } else {
                state[policiesData.domainName] = {
                    policies: { ...policiesData },
                };
            }
            return { ...state };
        }

        case STORE_HISTORY: {
            const { historyData: historyData } = payload;
            if (state[historyData.domainName]) {
                state[historyData.domainName].history = historyData;
            } else {
                state[historyData.domainName] = { history: { ...historyData } };
            }
            return { ...state };
        }

        case RETURN_DOMAIN_LIST: {
            return state;
        }
        default:
            return state;
    }
};
