import { LOAD_HISTORY, RETURN_HISTORY } from '../actions/history';
import JsonUtils from '../../components/utils/JsonUtils';

export const domainHistory = (state = {}, action) => {
    const { type, payload } = action;
    switch (type) {
        case LOAD_HISTORY: {
            const { domainHistory, domainName, expiry } = payload;
            return { domainName: domainName, expiry: expiry, domainHistory: JsonUtils.omitUndefined(domainHistory) };
        }
        case RETURN_HISTORY:
            return state;
        default:
            return state;
    }
};
