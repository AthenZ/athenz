export const LOAD_DOMAIN_DATA = 'LOAD_DOMAIN_DATA';
export const loadDomainData = (domainData, domainName, expiry) => ({
    type: LOAD_DOMAIN_DATA,
    payload: { domainData, domainName, expiry },
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

export const RETURN_DOMAIN_DATA = 'RETURN_DOMAIN_DATA';
export const returnDomainData = () => ({
    type: RETURN_DOMAIN_DATA,
});

export const LOAD_DOMAIN_HISTORY_TO_STORE = 'LOAD_DOMAIN_HISTORY_TO_STORE';
export const loadDomainHistoryToStore = (history) => ({
    type: LOAD_DOMAIN_HISTORY_TO_STORE,
    payload: { history },
});

export const UPDATE_BUSINESS_SERVICE_IN_STORE =
    'UPDATE_BUSINESS_SERVICE_IN_STORE';
export const updateBusinessServiceInStore = (businessServiceName) => ({
    type: UPDATE_BUSINESS_SERVICE_IN_STORE,
    payload: { businessServiceName },
});

export const LOAD_AUTHORITY_ATTRIBUTES = 'LOAD_AUTHORITY_ATTRIBUTES';
export const loadAuthorityAttributes = (authorityAttributes) => ({
    type: LOAD_AUTHORITY_ATTRIBUTES,
    payload: { authorityAttributes },
});
