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
