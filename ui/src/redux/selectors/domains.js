export const thunkSelectPendingDomainMembersList = (state, domainName) => {
    return state.domains[domainName] &&
        state.domains[domainName].domainData &&
        state.domains[domainName].domainData.pendingDomainMembersList
        ? state.domains[domainName].domainData.pendingDomainMembersList
        : undefined;
};

export const selectUserDomains = (state) => {
    return state.domains.domainsList;
};

export const selectDomain = (state, domainName) => {
    return selectUserDomains(state).find(
        (domain) => domain.name === domainName
    );
};

export const selectBusinessServicesAll = (state) => {
    return state.domains.businessServicesAll
        ? state.domains.businessServicesAll
        : [];
};

export const selectPendingDomainMembersList = (state, domainName) => {
    return state.domains[domainName] &&
        state.domains[domainName].domainData &&
        state.domains[domainName].domainData.pendingDomainMembersList
        ? state.domains[domainName].domainData.pendingDomainMembersList
        : [];
};

export const selectAllDomainsList = (state) => {
    return state.domains.allDomainsList ? state.domains.allDomainsList : [];
};

// export const selectDomainsCache = (state) => {
//     return state.domains.domainsCache || {};
// };
//
// export const selectDomainFromDomainsCache = (state, domainName) => {
//     return selectDomainsCache[domainName];
// };
//
// export const selectCollectionFromDomainCache = (state, domainName, collection) => {
//     const domain = selectDomainFromDomainsCache(state, domainName);
//     return domain ? domain[collection] : null;
// }
//
// export const selectExpiryFromDomainCache = (state, domainName, collection) => {
//     const domainCollection = selectCollectionFromDomainCache(state, domainName, collection);
//     return domainCollection ? domainCollection.expiry : null;
// }
