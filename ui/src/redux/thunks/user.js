import { getExpiryTime, isExpired } from '../utils';
import { selectUserPendingMembers } from '../selectors/user';
import API from '../../api';
import { loadUserPendingMembers } from '../actions/user';

export const getUserPendingMembers = () => async (dispatch, getState) => {
    let userPendingMembers = selectUserPendingMembers(getState());
    if (userPendingMembers === undefined || isExpired(getState().user.expiry)) {
        let userPendingMembersList = await API().getPendingDomainMembersList();
        const expiry = getExpiryTime();
        dispatch(loadUserPendingMembers(userPendingMembersList, expiry));
    }
};
