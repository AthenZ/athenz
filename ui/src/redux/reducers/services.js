import {
    ADD_SERVICE_TO_STORE,
    DELETE_KEY_FROM_STORE,
    DELETE_SERVICE_FROM_STORE,
    LOAD_SERVICES,
    RETURN_SERVICES,
} from '../actions/services';
import { getNowTime } from '../utils';

export const services = (state = {}, action) => {
    const { type, payload } = action;
    switch (type) {
        case LOAD_SERVICES: {
            const { services, domainName, expiry } = payload;
            return {
                domainName: domainName,
                expiry: expiry,
                services: services,
            };
        }
        case ADD_SERVICE_TO_STORE: {
            const { serviceFullName, serviceData } = payload;
            const { keyId, keyValue } = serviceData;
            state.services.push({
                name: serviceFullName,
                modified: getNowTime(),
                publicKeys: [{ key: keyValue, id: keyId }],
            });
            return { ...state };
        }
        case DELETE_SERVICE_FROM_STORE: {
            const { serviceFullName } = payload;
            let serviceList = state.services.filter(
                (service) => service.name !== serviceFullName
            );
            console.log(
                'to delete servie name is: ',
                serviceFullName,
                'the services list is: ',
                serviceList
            );
            state.services = serviceList;
            return { ...state };
        }
        case DELETE_KEY_FROM_STORE: {
            const { serviceFullName, keyId } = payload;
            console.log('serviceFullName', serviceFullName, 'keyId', keyId);
            let serviceIndex = state.services.findIndex(
                (service) => service.name === serviceFullName
            );
            console.log('serviceIndex', serviceIndex);
            if (serviceIndex === -1) {
                return state;
            }
            let publicKeyIndex = state.services[
                serviceIndex
            ].publicKeys.findIndex((publicKey) => publicKey.id === keyId);
            if (publicKeyIndex !== -1) {
                console.log('publicKeyIndex', publicKeyIndex);
                const newState = JSON.parse(JSON.stringify(state));
                newState.services[serviceIndex].publicKeys.splice(
                    publicKeyIndex,
                    1
                );
                return newState;
            }
            return state;
        }

        case RETURN_SERVICES:
            return state;
        default:
            return state;
    }
};
