export const selectDomainData = (state) => {
    return state.domainData.domainData ? state.domainData.domainData : {};
};

export const selectDomainAuditEnabled = (state) => {
    return selectDomainData(state).auditEnabled
        ? selectDomainData(state).auditEnabled
        : '';
};

export const selectDomainHeaderDetails = (state) => {
    return selectDomainData(state).headerDetails
        ? selectDomainData(state).headerDetails
        : {};
};

export const selectProductMasterLink = (state) => {
    return selectDomainData(state).headerDetails?.productMasterLink
        ? selectDomainData(state).headerDetails.productMasterLink
        : {};
};

export const selectUserLink = (state) => {
    return selectDomainData(state).headerDetails
        ? selectDomainData(state).headerDetails.userData.userLink
        : '';
};

export const selectHeaderDetails = (state) => {
    return selectDomainData(state).headerDetails
        ? selectDomainData(state).headerDetails
        : {};
};

export const selectPendingMembersList = (state) => {
    return selectDomainData(state).pendingMembersList
        ? selectDomainData(state).pendingMembersList
        : [];
};

export const selectDomainTags = (state) => {
    return selectDomainData(state).tags ? selectDomainData(state).tags : {};
};

export const selectFeatureFlag = (state) => {
    return selectDomainData(state).featureFlag
        ? selectDomainData(state).featureFlag
        : false;
};

export const selectHistoryRows = (state) => {
    return selectDomainData(state).history
        ? selectDomainData(state).history
        : [];
};

export const selectBusinessServices = (state) => {
    return selectDomainData(state).businessServices
        ? selectDomainData(state).businessServices
        : [];
};

export const selectAuthorityAttributes = (state) => {
    return state.domainData.authorityAttributes
        ? state.domainData.authorityAttributes
        : {};
};
