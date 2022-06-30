import {
    ADD_DOMAIN_TAGS_TO_STORE,
    LOAD_DOMAIN_DATA,
    RETURN_DOMAIN_DATA,
    UPDATE_DOMAIN_SETTINGS,
} from '../actions/domain-data';

export const domainData = (state = {}, action) => {
    const { type, payload } = action;
    switch (type) {
        case LOAD_DOMAIN_DATA: {
            const { domainData } = payload;
            return { ...domainData };
        }
        case UPDATE_DOMAIN_SETTINGS: {
            const { collectionMeta } = payload;
            return { ...state, ...collectionMeta };
        }
        case ADD_DOMAIN_TAGS_TO_STORE: {
            const { tags } = payload;
            let newState = { ...state };
            newState.tags = tags;
            console.log('ADD_DOMAIN_TAGS_TO_STORE', tags, newState);
            return { ...newState };
        }
        case RETURN_DOMAIN_DATA:
            return state;
        default:
            return state;
    }
};
