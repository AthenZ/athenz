import {
    LOAD_DOMAIN_DATA,
    LOAD_DOMAIN_HISTORY_TO_STORE, RETURN_DOMAIN_DATA,
    UPDATE_BUSINESS_SERVICE_IN_STORE,
} from '../actions/domain-data';
import produce from 'immer';
import {
    UPDATE_SETTING_TO_STORE,
    UPDATE_TAGS_TO_STORE,
} from '../actions/collections';

export const domainData = (state = {}, action) => {
    const { type, payload } = action;
    switch (type) {
        case LOAD_DOMAIN_DATA: {
            const { domainData, domainName, expiry } = payload;
            return { domainData, domainName, expiry };
        }
        case UPDATE_SETTING_TO_STORE: {
            const { collectionSettings, category } = payload;
            let newState = state;
            if (category === 'domain') {
                newState = produce(state, (draft) => {
                    draft.domainData = {
                        ...draft.domainData,
                        ...collectionSettings,
                    };
                });
            }
            return newState;
        }
        case UPDATE_TAGS_TO_STORE: {
            const { collectionTags, category } = payload;
            let newState = state;
            if (category === 'domain') {
                newState = produce(state, (draft) => {
                    draft.domainData.tags = collectionTags;
                });
            }
            return newState;
        }
        // TODO roy - need to test it
        case LOAD_DOMAIN_HISTORY_TO_STORE: {
            const { history } = payload;
            const newState = produce(state, (draft) => {
                draft.domainData.history = history;
            });
            return newState;
        }
        // TODO roy - need to test it
        case UPDATE_BUSINESS_SERVICE_IN_STORE: {
            const { businessServiceName } = payload;
            const newState = produce(state, (draft) => {
                draft.domainData.businessService = businessServiceName;
            });
            return newState;
        }
        case RETURN_DOMAIN_DATA:
        default:
            return state;
    }
};
