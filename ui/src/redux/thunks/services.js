import API from '../../api';
import { loadingInProcess, loadingSuccess } from '../actions/loading';
import {
    addServiceToStore,
    deleteKeyFromStore,
    deleteServiceFromStore,
    loadServices,
    returnServices,
} from '../actions/services';
import { storeServices } from '../actions/domains';
import { getExpiryTime } from '../utils';

const api = API();

const getFullName = (domain, name) => domain + '.' + name;
export const addService =
    (serviceName, service, _csrf, onSuccess, onFail) =>
    async (dispatch, getState) => {
        let serviceList = [];
        let domainName = getState().services.domainName;
        // problem if going to else maybe was added between refreshes
        if (getState().services.expiry <= 0) {
            serviceList = await api.getServices(domainName);
            dispatch(loadServices(serviceList, domainName, 5));
        } else {
            serviceList = getState().services.services;
        }

        if (
            serviceList.find(
                (service) =>
                    getFullName(domainName, serviceName) === service.name
            )
        ) {
            // TODO mendi - to verify that
            onFail({
                statusCode: 409,
                body: { message: `${serviceName} already exist` },
            });
        } else {
            api.addService(
                domainName,
                serviceName,
                service.description,
                service.providerEndpoint,
                service.keyId,
                service.keyValue,
                _csrf
            )
                .then(() => {
                    dispatch(
                        addServiceToStore(
                            getFullName(domainName, serviceName),
                            service
                        )
                    );
                    onSuccess(`${domainName}-${serviceName}`, false);
                })
                .catch((err) => {
                    onFail(err);
                });
        }
    };

export const deleteService =
    (serviceName, _csrf, onSuccess, onFail) => async (dispatch, getState) => {
        let domainName = getState().services.domainName;
        await api
            .deleteService(domainName, serviceName, _csrf)
            .then(() => {
                console.log('in then delete service');
                dispatch(
                    deleteServiceFromStore(getFullName(domainName, serviceName))
                );
                onSuccess();
            })
            .catch((err) => {
                onFail(err);
            });
    };

export const deleteKey =
    (serviceName, deleteKeyId, _csrf, onSuccess, onFail) =>
    async (dispatch, getState) => {
        console.log('in delete key');
        let domainName = getState().services.domainName;
        await api
            .deleteKey(domainName, serviceName, deleteKeyId, _csrf)
            .then(() => {
                console.log('in then delete key');
                dispatch(
                    deleteKeyFromStore(
                        getFullName(domainName, serviceName),
                        deleteKeyId
                    )
                );
                onSuccess();
            })
            .catch((err) => {
                onFail(err);
            });
    };

export const getServices = (domainName) => async (dispatch, getState) => {
    if (getState().services.expiry) {
        if (getState().services.domainName !== domainName) {
            dispatch(loadingInProcess('getServices'));
            dispatch(storeServices(getState().services));
            if (
                getState().domains[domainName] &&
                getState().domains[domainName].services &&
                getState().domains[domainName].services.expiry > 0
            ) {
                dispatch(
                    loadServices(
                        getState().domains[domainName].services,
                        domainName,
                        getState().domains[domainName].services.expiry
                    )
                );
            } else {
                const serviceList = await api.getServices(
                    domainName,
                    true,
                    true
                );
                dispatch(loadServices(serviceList));
                dispatch(loadingSuccess('getServices'));
            }
        } else if (getState().services.expiry <= 0) {
            if (getState().services.domainName !== domainName) {
                dispatch(storeServices(getState().services));
            }
            dispatch(loadingInProcess('getServices'));
            const serviceList = await api.getServices(domainName, true, true);
            const expiry = getExpiryTime();
            dispatch(loadServices(serviceList, domainName, expiry));
            dispatch(loadingSuccess('getServices'));
        } else {
            dispatch(returnServices());
        }
    } else {
        dispatch(loadingInProcess('getServices'));
        const serviceList = await api.getServices(domainName, true, true);
        const expiry = getExpiryTime();
        console.log('in get service with: ', serviceList);
        dispatch(loadServices(serviceList, domainName, expiry));
        dispatch(loadingSuccess('getServices'));
    }
};
