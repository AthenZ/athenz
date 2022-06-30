import { LOAD_TEMPLATES, RETURN_TEMPLATES } from '../actions/templates';

export const templates = (state = {}, action) => {
    const { type, payload } = action;
    switch (type) {
        case LOAD_TEMPLATES: {
            const { domainTemplates, serverTemplates, domainName, expiry } =
                payload;
            return {
                domainName: domainName,
                expiry: expiry,
                domainTemplates: domainTemplates,
                serverTemplates: serverTemplates,
            };
        }
        case RETURN_TEMPLATES:
            return state;
        default:
            return state;
    }
};
