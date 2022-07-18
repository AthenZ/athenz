import API from '../../api';

import {
    addKeyToStore,
    addProviderToStore,
    addServiceToStore,
    allowProviderTemplateToStore,
    deleteKeyFromStore,
    deleteServiceFromStore,
    loadServices,
    returnServices,
} from '../actions/services';
import { storeServices } from '../actions/domains';
import { getFullName, isExpired } from '../utils';
import { getServicesApiCall } from './utils/services';
import { thunkSelectService, thunkSelectServices } from '../selectors/services';
import { serviceDelimiter } from '../config';

const api = API();

export const addService =
    (domainName, service, _csrf) => async (dispatch, getState) => {
        await dispatch(getServices(domainName));
        let serviceMap = thunkSelectServices(getState());
        if (
            serviceMap[getFullName(domainName, serviceDelimiter, service.name)]
        ) {
            return Promise.reject({
                statusCode: 409,
                body: { message: `${service.name} already exist` },
            });
        } else {
            try {
                await api.addService(
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
            return Promise.reject({
                statusCode: 404,
                body: { message: `${serviceName} does not exist` },
            });
        }
        try {
            await api.deleteService(domainName, serviceName, _csrf);
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
        dispatch(getServices(domainName));
        let currService = thunkSelectService(
            getState(),
            domainName,
            serviceName
        );
        if (currService && currService.publicKeys[deleteKeyId] === undefined) {
            return Promise.reject({
                statusCode: 404,
                body: { message: `${deleteKeyId} not found` },
            });
        }
        try {
            await api.deleteKey(domainName, serviceName, deleteKeyId, _csrf);
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
        dispatch(getServices(domainName));
        let currService = thunkSelectService(
            getState(),
            domainName,
            serviceName
        );
        if (currService && currService.publicKeys[keyId]) {
            return Promise.reject({
                statusCode: 409,
                body: { message: `key id ${keyId} already exist` },
            });
        }
        await api
            .addKey(domainName, serviceName, keyId, keyValue, _csrf)
            .then(() => {
                dispatch(
                    addKeyToStore(
                        getFullName(domainName, serviceDelimiter, serviceName),
                        keyId,
                        keyValue
                    )
                );
                return Promise.resolve();
            })
            .catch((err) => {
                return Promise.reject(err);
            });
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
                let data = await api.getProvider(domainName, serviceName);
                dispatch(
                    addProviderToStore(
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
            await api.allowProviderTemplate(
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
        api.getInstances(domainName, serviceName, category)
            .then((data) => {
                console.log(data);
            })
            .catch((err) => {
                console.log(err);
            });
    };
