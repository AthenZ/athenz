import { LOAD_PENDING_MEMBERS } from '../actions/user';

export const user = (state = {}, action) => {
    const { type, payload } = action;
    switch (type) {
        case LOAD_PENDING_MEMBERS: {
            const { pendingMembers, expiry } = payload;
            return { ...state, pendingMembers, expiry };
        }
        default:
            return state;
    }
};
