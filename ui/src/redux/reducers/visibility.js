import {
    LOAD_SERVICE_DEPENDENCIES,
    RETURN_SERVICE_DEPENDENCIES,
} from '../actions/visibility';

export const serviceDependencies = (state = {}, action) => {
    const { type, payload } = action;
    switch (type) {
        case LOAD_SERVICE_DEPENDENCIES: {
            const { serviceDependencies, domainName, expiry } = payload;
            return {
                domainName,
                expiry,
                serviceDependencies,
            };
        }
        case RETURN_SERVICE_DEPENDENCIES:
        default:
            return state;
    }
};
