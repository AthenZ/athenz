export const LOAD_DOMAIN_DATA = 'LOAD_DOMAIN_DATA';
export const loadDomainData = (domainData, domainName, expiry) => ({
    type: LOAD_DOMAIN_DATA,
    payload: { domainData, domainName, expiry },
});

export const LOAD_DOMAIN_HISTORY_TO_STORE = 'LOAD_DOMAIN_HISTORY_TO_STORE';
export const loadDomainHistoryToStore = (history) => ({
    type: LOAD_DOMAIN_HISTORY_TO_STORE,
    payload: { history },
});

export const RETURN_DOMAIN_DATA = 'RETURN_DOMAIN_DATA';
export const returnDomainData = () => ({
    type: RETURN_DOMAIN_DATA,
});

export const UPDATE_BUSINESS_SERVICE_IN_STORE =
    'UPDATE_BUSINESS_SERVICE_IN_STORE';
export const updateBusinessServiceInStore = (businessServiceName) => ({
    type: UPDATE_BUSINESS_SERVICE_IN_STORE,
    payload: { businessServiceName },
});
