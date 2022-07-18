import API from '../../api';
import {
    loadAuthorityAttributes,
    loadDomainData,
    loadDomainHistoryToStore,
    returnDomainData,
    updateBusinessServiceInStore,
} from '../actions/domain-data';
import { loadingInProcess, loadingSuccess } from '../actions/loading';
import { storeDomainData } from '../actions/domains';
import { getExpiryTime, isExpired } from '../utils';

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

const loadAllDomainData =
    (domainName, userName) => async (dispatch, getStore) => {
        dispatch(loadingInProcess('getDomainData'));
        const domainData = await getApi().getDomain(domainName);
        const isAwsTemplateApplied = await getApi().isAWSTemplateApplied(domainName);
        domainData.isAWSTemplateApplied = isAwsTemplateApplied;
        const headerDetails = await getApi().getHeaderDetails();
        domainData.headerDetails = headerDetails;
        const pendingMembersList = await getApi().getPendingDomainMembersList();
        domainData.pendingMembersList = pendingMembersList;
        const featureFlag = await getApi().getFeatureFlag();
        domainData.featureFlag = featureFlag;
        let authorityAttributes = await getApi().getAuthorityAttributes();
        domainData.authorityAttributes = authorityAttributes;
        let bServicesParams = {
            category: 'domain',
            attributeName: 'businessService',
            userName: userName,
        };

        const businessServices = await getApi().getMeta(bServicesParams);
        let businessServiceOptions = [];
        if (businessServices.validValues) {
            businessServices.validValues.forEach((businessService) => {
                let bServiceOnlyId = businessService.substring(
                    0,
                    businessService.indexOf(':')
                );
                let bServiceOnlyName = businessService.substring(
                    businessService.indexOf(':') + 1
                );
                businessServiceOptions.push({
                    value: bServiceOnlyId,
                    name: bServiceOnlyName,
                });
            });
        }
        domainData.businessServices = businessServiceOptions;

        const expiry = getExpiryTime();
        dispatch(loadDomainData(domainData, domainName, expiry));
        dispatch(loadingSuccess('getDomainData'));
    };

export const getDomainData =
    (domainName, userName) => async (dispatch, getState) => {
        if (getState().domainData.expiry) {
            if (getState().domainData.domainName !== domainName) {
                dispatch(storeDomainData(getState().domainData));
                if (
                    getState().domains[domainName] &&
                    getState().domains[domainName].domainData &&
                    !isExpired(getState().domains[domainName].domainData.expiry)
                ) {
                    dispatch(
                        loadDomainData(
                            getState().domains[domainName].domainData
                                .domainData,
                            domainName,
                            getState().domains[domainName].domainData.expiry
                        )
                    );
                } else {
                    await dispatch(loadAllDomainData(domainName, userName));
                }
            } else if (isExpired(getState().domainData.expiry)) {
                await dispatch(loadAllDomainData(domainName, userName));
            } else {
                dispatch(returnDomainData());
            }
        } else {
            await dispatch(loadAllDomainData(domainName, userName));
        }
    };

export const getDomainHistory =
    (domainName, startDate, endDate, _csrf, roleName = 'ALL') =>
    async (dispatch, getStore) => {
        try {
            let history = await getApi().getHistory(
                domainName,
                roleName,
                startDate,
                endDate,
                _csrf
            );
            dispatch(loadDomainHistoryToStore(history));
            return Promise.resolve(history);
        } catch (error) {
            return Promise.reject(error);
        }
    };

export const updateBusinessService =
    (domainName, meta, auditMsg, csrf, category) =>
    async (dispatch, getState) => {
        try {
            await getApi().putMeta(
                domainName,
                domainName,
                meta,
                auditMsg,
                csrf,
                category
            );
            dispatch(updateBusinessServiceInStore(meta.businessService));
            return Promise.resolve();
        } catch (e) {
            return Promise.reject(e);
        }
    };
