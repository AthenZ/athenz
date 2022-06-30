import { mapToList } from '../utils';

export const selectDomainAuditEnabled = (state) => {
    return state.domainData.auditEnabled
        ? state.domainData.auditEnabled
        : false;
};
// export const selectDomainName = (state) => state.domainData.domainName;

export const selectDomainData = (state) => {
    return state.domainData;
};

export const selectDomainHeaderDetails = (state) => {
    return state.domainData.headerDetails ? state.domainData.headerDetails : {};
};

export const selectProductMasterLink = (state) => {
    return state.domainData.headerDetails
        ? state.domainData.headerDetails.productMasterLink
        : '';
};

export const selectUserLink = (state) => {
    return state.domainData.headerDetails
        ? state.domainData.headerDetails.userData.userLink
        : '';
};

export const selectHeaderDetails = (state) => {
    return state.domainData.headerDetails;
};

export const selectPendingMembersList = (state) => {
    return state.domainData.pendingMembersList;
};

export const selectDomainTags = (state) => {
    return state.domainData.tags ? state.domainData.tags : {};
};
