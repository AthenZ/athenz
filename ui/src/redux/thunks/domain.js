import API from '../../api';
import {
    loadDomainData,
    returnDomainData,
    updateDomainSettings,
} from '../actions/domain-data';
import { loadingInProcess, loadingSuccess } from '../actions/loading';
import { storeDomainData } from '../actions/domains';
import { updateGroupSettings } from '../actions/groups';

const api = API();

export const updateSettings =
    (collectionMeta, collectionName, _csrf, category, onSuccess, onFail) =>
    async (dispatch, getStore) => {
        let domainName = getStore().domainData.name;
        api.putMeta(
            domainName,
            collectionName,
            collectionMeta,
            'Updated domain Meta using Athenz UI',
            _csrf,
            category
        )
            .then(() => {
                if (category === 'domain') {
                    dispatch(updateDomainSettings(collectionMeta));
                } else if (category === 'group') {
                    console.log('in group');
                    dispatch(
                        updateGroupSettings(collectionName, collectionMeta)
                    );
                }
                onSuccess();
            })
            .catch((err) => {
                onFail(err);
            });
    };

const loadAllDomainData =
    (domainName, userName) => async (dispatch, getStore) => {
        // let bServicesParams = {
        //     category: 'domain',
        //     attributeName: 'businessService',
        //     userName: userName,
        // };
        dispatch(loadingInProcess('getDomainData'));
        const domainData = await api.getDomain(domainName);
        const isAwsTemplateApplied = await api.isAWSTemplateApplied(domainName);
        domainData.isAWSTemplateApplied = isAwsTemplateApplied;
        const headerDetails = await api.getHeaderDetails();
        domainData.headerDetails = headerDetails;
        const pendingMembersList = await api.getPendingDomainMembersList();
        domainData.pendingMembersList = pendingMembersList;
        const featureFlag = await api.getFeatureFlag();
        domainData.featureFlag = featureFlag;
        // const headerBusinessData = await api.getMeta(bServicesParams);
        // let businessServiceOptions = [];
        // if (headerBusinessData.validValues) {
        //     headerBusinessData.validValues.forEach((businessService) => {
        //         let bServiceOnlyId = businessService.substring(
        //             0,
        //             businessService.indexOf(':')
        //         );
        //         let bServiceOnlyName = businessService.substring(
        //             businessService.indexOf(':') + 1
        //         );
        //         businessServiceOptions.push({
        //             value: bServiceOnlyId,
        //             name: bServiceOnlyName,
        //         });
        //     });
        // }
        // domainData.businessData = businessServiceOptions;
        dispatch(loadDomainData(domainData));
        dispatch(loadingSuccess('getDomainData'));
    };

export const getDomainData =
    (domainName, userName) => async (dispatch, getStore) => {
        if (getStore().domainData.expiry) {
            if (getStore().domainData.expiry <= 0) {
                if (getStore().domainData.name !== domainName) {
                    dispatch(storeDomainData(getStore().domainData));
                }
                loadAllDomainData(domainName, userName);
            } else if (getStore().domainData.name !== domainName) {
                dispatch(storeDomainData(getStore().domainData));
                if (
                    getStore()[domainName] &&
                    getStore()[domainName].domainData
                ) {
                    dispatch(loadDomainData(getStore()[domainName].domainData));
                } else {
                    loadAllDomainData(domainName, userName);
                }
            } else {
                dispatch(returnDomainData());
            }
        } else {
            dispatch(loadAllDomainData(domainName, userName));
        }
    };
