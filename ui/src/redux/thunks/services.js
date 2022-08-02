import API from '../../api';

import {
    addKeyToStore,
    loadProvidersToStore,
    addServiceToStore,
    allowProviderTemplateToStore,
    deleteKeyFromStore,
    deleteServiceFromStore,
    loadServices,
    returnServices,
    loadInstancesToStore,
    loadServiceHeaderDetailsToStore,
} from '../actions/services';
import { storeServices } from '../actions/domains';
import {
    buildErrorForDoesntExistCase,
    buildErrorForDuplicateCase,
    getFullName,
    isExpired,
} from '../utils';
import { getServicesApiCall } from './utils/services';
import { thunkSelectService, thunkSelectServices } from '../selectors/services';
import { serviceDelimiter } from '../config';
import { loadingInProcess, loadingSuccess } from '../actions/loading';

export const addService =
    (domainName, service, _csrf) => async (dispatch, getState) => {
        await dispatch(getServices(domainName));
        let serviceMap = thunkSelectServices(getState());
        if (
            serviceMap[getFullName(domainName, serviceDelimiter, service.name)]
        ) {
            return Promise.reject(
                buildErrorForDuplicateCase('Service', service.name)
            );
        } else {
            try {
                await API().addService(
                    domainName,
                    service.name,
                    service.description,
                    service.providerEndpoint,
                    service.keyId,
                    service.keyValue,
                    _csrf
                );
                dispatch(
                    addServiceToStore(
                        getFullName(domainName, serviceDelimiter, service.name),
                        service
                    )
                );
                return Promise.resolve();
            } catch (err) {
                return Promise.reject(err);
            }
        }
    };

export const deleteService =
    (domainName, serviceName, _csrf) => async (dispatch, getState) => {
        await dispatch(getServices(domainName));
        let serviceMap = thunkSelectServices(getState());
        if (
            !(
                getFullName(domainName, serviceDelimiter, serviceName) in
                serviceMap
            )
        ) {
            return Promise.reject(
                buildErrorForDoesntExistCase('Service', serviceName)
            );
        }
        try {
            await API().deleteService(domainName, serviceName, _csrf);
            dispatch(
                deleteServiceFromStore(
                    getFullName(domainName, serviceDelimiter, serviceName)
                )
            );
            return Promise.resolve();
        } catch (err) {
            return Promise.reject(err);
        }
    };

export const deleteKey =
    (domainName, serviceName, deleteKeyId, _csrf) =>
    async (dispatch, getState) => {
        try {
            await dispatch(getServices(domainName));
            let currService = thunkSelectService(
                getState(),
                domainName,
                serviceName
            );
            if (
                currService &&
                currService.publicKeys[deleteKeyId] === undefined
            ) {
                return Promise.reject(
                    buildErrorForDoesntExistCase('Key id', deleteKeyId)
                );
            }
            await API().deleteKey(domainName, serviceName, deleteKeyId, _csrf);
            dispatch(
                deleteKeyFromStore(
                    getFullName(domainName, serviceDelimiter, serviceName),
                    deleteKeyId
                )
            );
            return Promise.resolve();
        } catch (err) {
            return Promise.reject(err);
        }
    };

export const addKey =
    (domainName, serviceName, keyId, keyValue, _csrf) =>
    async (dispatch, getState) => {
        await dispatch(getServices(domainName));
        let currService = thunkSelectService(
            getState(),
            domainName,
            serviceName
        );
        if (currService?.publicKeys && currService.publicKeys[keyId]) {
            return Promise.reject(buildErrorForDuplicateCase('Key id', keyId));
        }
        try {
            await API().addKey(domainName, serviceName, keyId, keyValue, _csrf);
            dispatch(
                addKeyToStore(
                    getFullName(domainName, serviceDelimiter, serviceName),
                    keyId,
                    keyValue
                )
            );
            return Promise.resolve();
        } catch (err) {
            return Promise.reject(err);
        }
    };

export const getServices = (domainName) => async (dispatch, getState) => {
    if (getState().services.expiry) {
        if (getState().services.domainName !== domainName) {
            dispatch(storeServices(getState().services));
            if (
                getState().domains[domainName] &&
                getState().domains[domainName].services &&
                !isExpired(getState().domains[domainName].services.expiry)
            ) {
                dispatch(
                    loadServices(
                        getState().domains[domainName].services.services,
                        domainName,
                        getState().domains[domainName].services.expiry
                    )
                );
            } else {
                await getServicesApiCall(domainName, dispatch);
            }
        } else if (isExpired(getState().services.expiry)) {
            await getServicesApiCall(domainName, dispatch);
        } else {
            dispatch(returnServices());
        }
    } else {
        await getServicesApiCall(domainName, dispatch);
    }
};

export const getProvider =
    (domainName, serviceName) => async (dispatch, getState) => {
        await dispatch(getServices(domainName));
        let currService = thunkSelectService(
            getState(),
            domainName,
            serviceName
        );
        if (
            currService &&
            currService.provider &&
            !isExpired(currService.provider.expiry)
        ) {
            return Promise.resolve();
        } else {
            try {
                let data = await API().getProvider(domainName, serviceName);
                dispatch(
                    loadProvidersToStore(
                        getFullName(domainName, serviceDelimiter, serviceName),
                        data.provider,
                        data.allProviders
                    )
                );
                return Promise.resolve();
            } catch (err) {
                return Promise.reject(err);
            }
        }
    };

export const allowProviderTemplate =
    (domainName, serviceName, providerId, _csrf) =>
    async (dispatch, getState) => {
        try {
            await dispatch(getProvider(domainName, serviceName));
            await API().allowProviderTemplate(
                domainName,
                serviceName,
                providerId,
                _csrf
            );
            dispatch(
                allowProviderTemplateToStore(
                    getFullName(domainName, serviceDelimiter, serviceName),
                    providerId
                )
            );
            return Promise.resolve();
        } catch (err) {
            return Promise.reject(err);
        }
    };

export const getServiceInstances =
    (domainName, serviceName, category) => async (dispatch, getState) => {
        try {
            await dispatch(getServices(domainName));
            let dynamicInstances = API().getInstances(
                domainName,
                serviceName,
                category
            );
            dispatch(
                loadInstancesToStore(
                    getFullName(domainName, serviceDelimiter, serviceName),
                    category,
                    dynamicInstances
                )
            );
        } catch (err) {
            return Promise.reject(err);
        }
    };

export const getServiceHeaderDetails =
    (domainName, serviceName) => async (dispatch, getState) => {
        try {
            await dispatch(getServices(domainName));
            dispatch(loadingInProcess('getServiceHeaderDetails'));
            let data = await API().getServiceHeaderDetails();
            dispatch(
                loadServiceHeaderDetailsToStore(
                    getFullName(domainName, serviceDelimiter, serviceName),
                    data
                )
            );
        } catch (err) {
            return Promise.reject(err);
        } finally {
            dispatch(loadingSuccess('getServiceHeaderDetails'));
        }
    };
