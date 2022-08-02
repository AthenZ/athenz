import API from '../../api';
import {
    loadDomainData,
    loadDomainHistoryToStore, returnDomainData,
    updateBusinessServiceInStore,
} from '../actions/domain-data';
import { loadingInProcess, loadingSuccess } from '../actions/loading';
import { storeDomainData } from '../actions/domains';
import { getExpiryTime, isExpired } from '../utils';

const loadAllDomainData = async (domainName, userName, dispatch) =>  {
        dispatch(loadingInProcess('getDomainData'));
        const domainData = await API().getDomain(domainName);
        const isAwsTemplateApplied = await API().isAWSTemplateApplied(
            domainName
        );
        domainData.isAWSTemplateApplied = isAwsTemplateApplied;
        const headerDetails = await API().getHeaderDetails();
        domainData.headerDetails = headerDetails;
        const domainPendingMembersList =
            await API().getPendingDomainMembersListByDomain(domainName);
        domainData.pendingMembersList = domainPendingMembersList;
        const featureFlag = await API().getFeatureFlag();
        domainData.featureFlag = featureFlag;
        let authorityAttributes = await API().getAuthorityAttributes();
        domainData.authorityAttributes = authorityAttributes;
        let bServicesParams = {
            category: 'domain',
            attributeName: 'businessService',
            userName: userName,
        };

        const businessServices = await API().getMeta(bServicesParams);
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
                    await loadAllDomainData(domainName, userName, dispatch);
                }
            } else if (isExpired(getState().domainData.expiry)) {
                await loadAllDomainData(domainName, userName, dispatch);
            } else {
                dispatch(returnDomainData());
            }
        } else {
            await loadAllDomainData(domainName, userName, dispatch);
        }
    };

// TODO roy - think if is necessary
export const getDomainHistory =
    (domainName, startDate, endDate, _csrf, roleName = 'ALL') =>
    async (dispatch, getState) => {
        try {
            let history = await API().getHistory(
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
            await API().putMeta(
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
