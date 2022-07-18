import {
    ADD_DOMAIN_TAGS_TO_STORE,
    LOAD_AUTHORITY_ATTRIBUTES,
    LOAD_DOMAIN_DATA,
    LOAD_DOMAIN_HISTORY_TO_STORE,
    RETURN_DOMAIN_DATA,
    UPDATE_BUSINESS_SERVICE_IN_STORE,
    UPDATE_DOMAIN_SETTINGS,
} from '../actions/domain-data';
import produce from 'immer';

export const domainData = (state = {}, action) => {
    const { type, payload } = action;
    switch (type) {
        case LOAD_DOMAIN_DATA: {
            const { domainData, domainName, expiry } = payload;
            return { domainData, domainName, expiry };
        }
        case UPDATE_DOMAIN_SETTINGS: {
            const { collectionMeta } = payload;
            let newState = produce(state, (draft) => {
                draft.domainData = { ...draft.domainData, ...collectionMeta };
            });
            return newState;
        }
        case ADD_DOMAIN_TAGS_TO_STORE: {
            const { tags } = payload;
            const newState = produce(state, (draft) => {
                draft.domainData.tags = tags;
            });
            return newState;
        }
        case LOAD_DOMAIN_HISTORY_TO_STORE: {
            const { history } = payload;
            const newState = produce(state, (draft) => {
                draft.domainData.history = history;
            });
            return newState;
        }
        case UPDATE_BUSINESS_SERVICE_IN_STORE: {
            const { businessServiceName } = payload;
            const newState = produce(state, (draft) => {
                draft.domainData.businessService = businessServiceName;
            });
            return newState;
        }
        case RETURN_DOMAIN_DATA:
            return state;
        case LOAD_AUTHORITY_ATTRIBUTES: {
            const { authorityAttributes } = payload;
            const newState = produce(state, (draft) => {
                draft.domainData.authorityAttributes = authorityAttributes;
            });
            return newState;
        }
        default:
            return state;
    }
};
