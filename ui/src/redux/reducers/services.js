import {
    ADD_KEY_TO_STORE,
    ADD_SERVICE_TO_STORE,
    ALLOW_PROVIDER_TEMPLATE_TO_STORE,
    DELETE_KEY_FROM_STORE,
    DELETE_SERVICE_FROM_STORE,
    LOAD_INSTANCES_TO_STORE,
    LOAD_PROVIDER_TO_STORE,
    LOAD_SERVICE_HEADER_DETAILS_TO_STORE,
    LOAD_SERVICES,
    RETURN_SERVICES,
} from '../actions/services';
import { getExpiryTime } from '../utils';
import produce from 'immer';

export const services = (state = {}, action) => {
    const { type, payload } = action;
    switch (type) {
        case LOAD_SERVICES: {
            const { services, domainName, expiry } = payload;
            return {
                domainName,
                expiry,
                services,
            };
        }
        case ADD_SERVICE_TO_STORE: {
            const { serviceFullName, serviceData } = payload;
            const { keyId, keyValue } = serviceData;
            let newState = produce(state, (draft) => {
                draft.services[serviceFullName] = {
                    name: serviceFullName,
                    // modified: getCurrentTime(),
                    publicKeys: { [keyId]: { key: keyValue, id: keyId } },
                };
            });
            return newState;
        }
        case DELETE_SERVICE_FROM_STORE: {
            const { serviceFullName } = payload;
            let newState = produce(state, (draft) => {
                delete draft.services[serviceFullName];
            });
            return newState;
        }
        case DELETE_KEY_FROM_STORE: {
            const { serviceFullName, keyId } = payload;
            let newState = produce(state, (draft) => {
                delete draft.services[serviceFullName].publicKeys[keyId];
            });
            return newState;
        }
        case ADD_KEY_TO_STORE: {
            const { serviceFullName, keyId, keyValue } = payload;
            let newState = produce(state, (draft) => {
                draft.services[serviceFullName].publicKeys[keyId] = {
                    key: keyValue,
                    id: keyId,
                };
            });
            return newState;
        }
        case LOAD_PROVIDER_TO_STORE: {
            const { serviceFullName, provider, allProviders } = payload;
            let newState = produce(state, (draft) => {
                if (draft.allProviders === undefined) {
                    draft.allProviders = allProviders;
                }
                draft.services[serviceFullName].provider = provider;
                draft.services[serviceFullName].provider.expiry =
                    getExpiryTime();
            });
            return newState;
        }
        case ALLOW_PROVIDER_TEMPLATE_TO_STORE: {
            const { serviceFullName, providerId } = payload;
            let newState = produce(state, (draft) => {
                draft.services[serviceFullName].provider[providerId] = 'allow';
            });
            return newState;
        }
        case LOAD_INSTANCES_TO_STORE:
            const { serviceFullName, category, instances } = payload;
            let newState = state;
            if (category === 'dynamic') {
                newState = produce(state, (draft) => {
                    draft.services[serviceFullName].dynamicInstances =
                        instances;
                });
            } else {
                newState = produce(state, (draft) => {
                    draft.services[serviceFullName].staticInstances = instances;
                });
            }
            return newState;
        case LOAD_SERVICE_HEADER_DETAILS_TO_STORE: {
            const { serviceFullName, serviceHeaderDetails } = payload;
            let newState = produce(state, (draft) => {
                draft.services[serviceFullName].serviceHeaderDetails =
                    serviceHeaderDetails;
            });
            return newState;
        }
        case RETURN_SERVICES:
            return state;
        default:
            return state;
    }
};
