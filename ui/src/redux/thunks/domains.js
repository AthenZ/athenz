import { loadingInProcess, loadingSuccess } from '../actions/loading';
import API from '../../api';
import {
    returnDomainList,
    loadUserDomainList,
    addSubDomainToStore,
    deleteSubDomainFromStore,
    addUserDomainToStore,
    loadBusinessServicesAll,
    returnBusinessServicesAll,
    loadAllDomainsList,
    loadPendingDomainMembersList,
    processPendingMembersToStore,
} from '../actions/domains';
import { getFullName } from '../utils';
import { subDomainDelimiter } from '../config';
import {
    selectDomain,
    thunkSelectPendingDomainMembersList,
} from '../selectors/domains';

const getApi = (() => {
    let api;
    return () => {
        if (api) {
            return api;
        }
        api = API();
        return api;
    }
})();

export const getUserDomainsList = () => async (dispatch, getState) => {
    try {
        if (
            !getState().domains.domainsList ||
            getState().domains.domainsList.length === 0
        ) {
            dispatch(loadingInProcess('getUserDomainsList'));
            const domainsList = await getApi().listUserDomains();
            dispatch(loadUserDomainList(domainsList));
            dispatch(loadingSuccess('getUserDomainsList'));
        } else {
            dispatch(returnDomainList());
        }
    } catch (err) {
        // let response = RequestUtils.errorCheckHelper(err);
        // let reload = response.reload;
        // let error = response.error;
    }
};

export const getBusinessServicesAll = () => async (dispatch, getState) => {
    let bServicesParamsAll = {
        category: 'domain',
        attributeName: 'businessService',
    };
    if (getState().domains.businessServicesAll) {
        dispatch(returnBusinessServicesAll());
    } else {
        const allBusinessServices = await getApi().getMeta(bServicesParamsAll);
        let businessServiceOptionsAll = [];
        if (allBusinessServices && allBusinessServices.validValues) {
            allBusinessServices.validValues.forEach((businessService) => {
                let bServiceOnlyId = businessService.substring(
                    0,
                    businessService.indexOf(':')
                );
                let bServiceOnlyName = businessService.substring(
                    businessService.indexOf(':') + 1
                );
                businessServiceOptionsAll.push({
                    value: bServiceOnlyId,
                    name: bServiceOnlyName,
                });
            });
        }
        dispatch(loadBusinessServicesAll(businessServiceOptionsAll));
    }
};

export const getDomain = (domainName) => async (dispatch, getState) => {
    try {
        await dispatch(getUserDomainsList());
        const domain = selectDomain(getState(), domainName);
        if (domain) {
            return Promise.resolve(domain);
        }
    } catch (e) {
        return Promise.reject(e);
    }
};

export const createSubDomain =
    (parentDomain, subDomain, adminUser, _csrf) =>
    async (dispatch, getState) => {
        try {
            await dispatch(getUserDomainsList());
            const domainName = getFullName(
                parentDomain,
                subDomainDelimiter,
                subDomain
            );
            const domain = selectDomain(getState(), domainName);
            if (domain) {
                return Promise.reject({
                    statusCode: 409,
                    body: { message: `domain ${domainName} already exist` },
                });
            }
            await getApi().createSubDomain(
                parentDomain,
                subDomain,
                adminUser,
                _csrf
            );
            dispatch(addSubDomainToStore(domainName));
            return Promise.resolve();
        } catch (e) {
            return Promise.reject(e);
        }
    };

export const createUserDomain =
    (userId, _csrf) => async (dispatch, getState) => {
        try {
            await getApi().createUserDomain(userId, _csrf);
            dispatch(addUserDomainToStore('home.' + userId));
            return Promise.resolve();
        } catch (e) {
            return Promise.reject(e);
        }
    };

export const deleteSubDomain =
    (parentDomain, domain, auditRef, _csrf) => async (dispatch, getState) => {
        try {
            await getApi().deleteSubDomain(parentDomain, domain, auditRef, _csrf);
            dispatch(
                deleteSubDomainFromStore(
                    getFullName(parentDomain, subDomainDelimiter, domain)
                )
            );
            return Promise.resolve();
        } catch (e) {
            return Promise.reject(e);
        }
    };

export const getAllDomainsList = () => async (dispatch, getState) => {
    if (
        getState().domains.allDomainsList === undefined ||
        getState().domains.allDomainsList.length === 0
    ) {
        dispatch(loadingInProcess('getAllDomainsList'));
        try {
            let domainsList = await getApi().listAllDomains();
            dispatch(loadAllDomainsList(domainsList));
            return Promise.resolve();
        } catch (err) {
            return Promise.reject(err);
        } finally {
            dispatch(loadingSuccess('getAllDomainsList'));
        }
    }
};

export const getPendingDomainMembersListByDomain =
    (domainName) => async (dispatch, getState) => {
        if (
            domainName !== null &&
            thunkSelectPendingDomainMembersList(getState(), domainName) ===
                undefined
        ) {
            try {
                dispatch(
                    loadingInProcess('getPendingDomainMembersListByDomain')
                );
                let pendingDomainMembersList =
                    await getApi().getPendingDomainMembersListByDomain(domainName);
                dispatch(
                    loadPendingDomainMembersList(
                        pendingDomainMembersList,
                        domainName
                    )
                );
                return Promise.resolve();
            } catch (err) {
                return Promise.reject(err);
            } finally {
                dispatch(loadingSuccess('getPendingDomainMembersListByDomain'));
            }
        }
    };

export const processPendingMembers =
    (domainName, roleName, memberName, auditRef, category, membership, _csrf) =>
    async (dispatch, getState) => {
        await getPendingDomainMembersListByDomain(domainName);
        try {
            await getApi().processPending(
                domainName,
                roleName,
                memberName,
                auditRef,
                category,
                membership,
                _csrf
            );
            dispatch(
                processPendingMembersToStore(domainName, membership, roleName)
            );
            return Promise.resolve();
        } catch (e) {
            return Promise.reject(e);
        }
    };

export const getPendingDomainMembersList = () => async (dispatch, getState) => {
    try {
        let pendingDomainMembersList = await getApi().getPendingDomainMembersList();
        dispatch(
            loadPendingDomainMembersList(pendingDomainMembersList, domainName)
        );
        return Promise.resolve();
    } catch (err) {
        return Promise.reject(err);
    } finally {
    }
};
