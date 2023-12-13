/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */

import { getExpiryTime, isExpired } from '../utils';
import {
    selectAllUsers,
    selectUserPendingMembers,
    selectUserResourceAccessList,
} from '../selectors/user';
import API from '../../api';
import {
    addUsersToStore,
    loadUserPendingMembers,
    loadUserResourceAccessList,
    returnUserResourceAccessList,
} from '../actions/user';

import {
    loadingFailed,
    loadingInProcess,
    loadingSuccess,
} from '../actions/loading';

export const getUserPendingMembers = () => async (dispatch, getState) => {
    const expiry = getExpiryTime();
    try {
        let userPendingMembers = selectUserPendingMembers(getState());
        if (
            userPendingMembers === undefined ||
            isExpired(getState().user.expiry)
        ) {
            let userPendingMembersList =
                await API().getPendingDomainMembersList();
            dispatch(loadUserPendingMembers(userPendingMembersList, expiry));
        }
    } catch (error) {
        // if error, set userPendingMembers to empty array
        dispatch(loadUserPendingMembers([], expiry));
    }
};

// TODO: Refactor getUserResourceAccessList redux fetching/storing to include mapping between action and resource accesslist
// consider case getUserResourceAccessList({action: 'abc'}) and getUserResourceAccessList({action: 'xyz'})
export const getUserResourceAccessList =
    (action) => async (dispatch, getState) => {
        let userResourceAccessList = selectUserResourceAccessList(getState());
        let isUserResourceAccessListEmpty =
            Array.isArray(userResourceAccessList) &&
            userResourceAccessList.length < 1;
        dispatch(loadingInProcess('getUserResourceAccessList'));
        if (isExpired(getState().user.expiry)) {
            try {
                userResourceAccessList = await API().getResourceAccessList(
                    action
                );
                const expiry = getExpiryTime();
                dispatch(
                    loadUserResourceAccessList(userResourceAccessList, expiry)
                );
                dispatch(loadingSuccess('getUserResourceAccessList'));
                return Promise.resolve();
            } catch (e) {
                dispatch(loadingFailed('getUserResourceAccessList'));
                return Promise.reject(e);
            }
        } else if (!isUserResourceAccessListEmpty) {
            dispatch(returnUserResourceAccessList());
        }
    };

export const getAllUsers = () => async (dispatch, getState) => {
    try {
        if (!selectAllUsers(getState())) {
            const userList = await API().getAllUsers();
            dispatch(addUsersToStore(userList.users));
        }
    } catch (e) {
        return Promise.reject(e);
    }
};
