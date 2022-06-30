export const GET_USER_DOMAINS_LIST = 'GET_USER_DOMAINS_LIST';
export const getDomainsList = () => ({
    type: GET_USER_DOMAINS_LIST,
});

export const LOAD_USER_DOMAINS_LIST = 'LOAD_USER_DOMAINS_LIST';
export const loadUserDomainList = (domainsList) => ({
    type: LOAD_USER_DOMAINS_LIST,
    payload: { domainList: domainsList },
});

export const LOAD_DOMAIN_DATA = 'LOAD_DOMAIN_DATA';
export const loadDomainData = (domainData) => ({
    type: LOAD_DOMAIN_DATA,
    payload: { domainData: domainData },
});

export const UPDATE_DOMAIN_SETTINGS = 'UPDATE_DOMAIN_SETTINGS';
export const updateDomainSettings = (collectionMeta) => ({
    type: UPDATE_DOMAIN_SETTINGS,
    payload: { collectionMeta: collectionMeta },
});

export const ADD_DOMAIN_TAGS_TO_STORE = 'ADD_DOMAIN_TAGS_TO_STORE';
export const addDomainTagToStore = (tags) => ({
    type: ADD_DOMAIN_TAGS_TO_STORE,
    payload: { tags },
});

// TODO - load all the domain data in one dispatch can cause a problem if 1 of the request fails then the whole domain fetch fails - but it was like this so far.

// export const LOAD_DOMAIN_HEADER_DETAILS = 'LOAD_DOMAIN_HEADER_DETAILS';
// export const loadHeaderDetails = (headerDetails) => ({
//     type: LOAD_DOMAIN_HEADER_DETAILS,
//     payload: { headerDetails: headerDetails },
// });
//
// export const LOAD_DOMAIN_MEMBERS_LIST = 'LOAD_DOMAIN_MEMBERS_LIST';
// export const loadPendingMembersList = (membersList) => ({
//     type: LOAD_DOMAIN_MEMBERS_LIST,
//     payload: { membersList: membersList },
// });
//
// export const LOAD_DOMAIN_FEATURE_FLAG = 'LOAD_DOMAIN_FEATURE_FLAG';
// export const loadFeatureFlag = (featureFlag) => ({
//     type: LOAD_DOMAIN_FEATURE_FLAG,
//     payload: { featureFlag: featureFlag },
// });
//
// export const LOAD_DOMAIN_BUSINESS_DATA = 'LOAD_DOMAIN_BUSINESS_DATA';
// export const loadHeaderBusinessData = (businessData) => ({
//     type: LOAD_DOMAIN_BUSINESS_DATA,
//     payload: { businessData: businessData },
// });
//
// export const LOAD_ALL_BUSINESS_DATA = 'LOAD_ALL_BUSINESS_DATA';
// export const loadAllBusinessData = (allBusinessData) => ({
//     type: LOAD_ALL_BUSINESS_DATA,
//     payload: { allBusinessData: allBusinessData },
// });
//
// export const LOAD_DOMAIN_DATA_FROM_STORE = 'LOAD_DOMAIN_DATA_FROM_STORE';
// export const loadDomainDataFromStore = (domainDataFromStore) => ({
//     type: LOAD_DOMAIN_DATA_FROM_STORE,
//     payload: { domainDataFromStore: domainDataFromStore },
// });

export const RETURN_DOMAIN_DATA = 'RETURN_DOMAIN_DATA';
export const returnDomainData = (domainData) => ({
    type: RETURN_DOMAIN_DATA,
    payload: { domainData: domainData },
});
