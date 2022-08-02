export const thunkSelectPendingDomainMembersList = (state, domainName) => {
    return state.domains[domainName] &&
        state.domains[domainName].domainData &&
        state.domains[domainName].domainData.pendingDomainMembersList
        ? state.domains[domainName].domainData.pendingDomainMembersList
        : undefined;
};

export const selectUserDomains = (state) => {
    return state.domains.domainsList ? state.domains.domainsList : [];
};

export const selectPersonalDomain = (state, domainName) => {
    return selectUserDomains(state)
        ? selectUserDomains(state).find((domain) => domain.name === domainName)
        : undefined;
};

export const selectBusinessServicesAll = (state) => {
    return state.domains.businessServicesAll
        ? state.domains.businessServicesAll
        : [];
};

export const selectAllDomainsList = (state) => {
    return state.domains.allDomainsList ? state.domains.allDomainsList : [];
};
