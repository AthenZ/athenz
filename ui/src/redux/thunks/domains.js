import {
    loadingFailed,
    loadingInProcess,
    loadingSuccess,
} from '../actions/loading';
import API from '../../api';
import {
    addDomainToUserDomainsList,
    deleteDomainFromUserDomainList,
    loadAllDomainsList,
    loadBusinessServicesAll,
    loadPendingDomainMembersList,
    loadUserDomainList,
    processPendingMembersToStore,
    returnBusinessServicesAll,
    returnDomainList,
} from '../actions/domains';
import { buildErrorForDuplicateCase, getFullName } from '../utils';
import { roleDelimiter, subDomainDelimiter } from '../config';
import {
    selectPersonalDomain,
    thunkSelectPendingDomainMembersList,
} from '../selectors/domains';

export const getUserDomainsList = () => async (dispatch, getState) => {
    try {
        if (
            !getState().domains.domainsList ||
            getState().domains.domainsList.length === 0
        ) {
            dispatch(loadingInProcess('getUserDomainsList'));
            const domainsList = await API().listUserDomains();
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
        const allBusinessServices = await API().getMeta(bServicesParamsAll);
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

export const createSubDomain =
    (parentDomain, subDomain, adminUser, _csrf) =>
    async (dispatch, getState) => {
        await dispatch(getUserDomainsList());
        const domainName = getFullName(
            parentDomain,
            subDomainDelimiter,
            subDomain
        );
        const domain = selectPersonalDomain(getState(), domainName);
        if (domain) {
            throw buildErrorForDuplicateCase('Domain', domainName);
        }
        await API().createSubDomain(parentDomain, subDomain, adminUser, _csrf);
        dispatch(addDomainToUserDomainsList(domainName));
        return Promise.resolve();
    };

export const createUserDomain =
    (userId, _csrf) => async (dispatch, getState) => {
        await API().createUserDomain(userId, _csrf);
        dispatch(addDomainToUserDomainsList('home.' + userId));
        return Promise.resolve();
    };

export const deleteSubDomain =
    (parentDomain, domain, auditRef, _csrf) => async (dispatch, getState) => {
        await API().deleteSubDomain(parentDomain, domain, auditRef, _csrf);
        dispatch(
            deleteDomainFromUserDomainList(
                getFullName(parentDomain, subDomainDelimiter, domain)
            )
        );
        return Promise.resolve();
    };

export const getAllDomainsList = () => async (dispatch, getState) => {
    if (
        getState().domains.allDomainsList === undefined ||
        getState().domains.allDomainsList.length === 0
    ) {
        dispatch(loadingInProcess('getAllDomainsList'));
        try {
            let domainsList = await API().listAllDomains();
            dispatch(loadAllDomainsList(domainsList));
            dispatch(loadingSuccess('getAllDomainsList'));
            return Promise.resolve();
        } catch (err) {
            dispatch(loadingFailed('getAllDomainsList'));
            return Promise.reject(err);
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
                    await API().getPendingDomainMembersListByDomain(domainName);
                dispatch(
                    loadPendingDomainMembersList(
                        pendingDomainMembersList,
                        domainName
                    )
                );
                dispatch(loadingSuccess('getPendingDomainMembersListByDomain'));
                return Promise.resolve();
            } catch (err) {
                dispatch(loadingFailed('getPendingDomainMembersListByDomain'));
                return Promise.reject(err);
            }
        }
    };

export const processPendingMembers =
    (domainName, roleName, memberName, auditRef, category, membership, _csrf) =>
    async (dispatch, getState) => {
        await dispatch(getPendingDomainMembersListByDomain(domainName));
        await API().processPending(
            domainName,
            roleName,
            memberName,
            auditRef,
            category,
            membership,
            _csrf
        );
        dispatch(
            processPendingMembersToStore(
                getFullName(domainName, roleDelimiter, roleName),
                membership
            )
        );
        return Promise.resolve();
    };
