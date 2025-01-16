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
    selectPendingMemberGroup,
    selectPendingMemberRole,
    selectUserPendingMembers,
    selectUserResourceAccessList,
} from '../selectors/user';
import API from '../../api';
import {
    addUsersToStore,
    loadUserPendingMembers,
    loadUserResourceAccessList,
    returnUserResourceAccessList,
    storePendingGroup,
    storePendingRole,
} from '../actions/user';

import {
    loadingFailed,
    loadingInProcess,
    loadingSuccess,
} from '../actions/loading';

const ROLE = 'role';
const GROUP = 'group';

const getPendingMemberRole = async (dispatch, state, domainName, roleName) => {
    let role = selectPendingMemberRole(state, domainName, roleName);
    if (!role || isExpired(role.expiry)) {
        role = await API().getRole(domainName, roleName, false, false, true);
        role.expiry = getExpiryTime();
        dispatch(storePendingRole(role, domainName, roleName));
    }
    return role;
};
const getPendingMemberGroup = async (
    dispatch,
    state,
    domainName,
    groupName
) => {
    let group = selectPendingMemberGroup(state, domainName, groupName);
    if (!group || isExpired(group.expiry)) {
        group = await API().getGroup(domainName, groupName, false, true);
        group.expiry = getExpiryTime();
        dispatch(storePendingGroup(group, domainName, groupName));
    }
    return group;
};

const prepareSelfServePendingMembers = async (
    pendingMembers,
    category,
    dispatch,
    state
) => {
    // SET MEMBER COMMENT AS AUDITREF FOR SELF-SERVE ROLES/GROUPS

    // set of domain:role/group to search for
    let roleOrGroupSet = new Set();
    Object.keys(pendingMembers).forEach((member) => {
        const memberData = pendingMembers[member];
        if (category === memberData.category) {
            roleOrGroupSet.add(
                `${memberData.domainName}:${memberData.roleName}`
            );
        }
    });

    // setup promises to get roles/groups
    let promises = [];
    roleOrGroupSet.forEach((entity) => {
        let [domain, role] = entity.split(':');
        if (category === ROLE) {
            promises.push(getPendingMemberRole(dispatch, state, domain, role));
        } else if (category === GROUP) {
            promises.push(getPendingMemberGroup(dispatch, state, domain, role));
        }
    });

    let data = await Promise.all(promises);

    // find which roles/groups have selfServe and assign comment as auditRef
    Object.keys(pendingMembers).forEach((memberName) => {
        const member = pendingMembers[memberName];
        if (member.category !== category) {
            return; // category is different (can be role or group)
        }
        // category matches
        for (let i = 0; i < data.length; i++) {
            const roleGroup = data[i];
            if (!roleGroup.selfServe) {
                continue; // we only look for self-serve roles/groups
            }
            const [domain, rest] = roleGroup.name.split(':');
            if (domain !== member.domainName) {
                break; // go to next "i" list containing roles/groups for diff domain
            }
            // domain matches
            const [princType, roleGroupName] = rest.split('.');
            if (roleGroupName === member.roleName) {
                // role/group name matches pending member's role/group and is self serve
                // set audetRef as provided comment
                member.auditRef = member.userComment;
                member.selfServe = true;
            }
        }
    });
};

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

            let promises = [];
            promises.push(
                prepareSelfServePendingMembers(
                    userPendingMembersList,
                    ROLE,
                    dispatch,
                    getState()
                )
            );
            promises.push(
                prepareSelfServePendingMembers(
                    userPendingMembersList,
                    GROUP,
                    dispatch,
                    getState()
                )
            );
            await Promise.all(promises);

            dispatch(loadUserPendingMembers(userPendingMembersList, expiry));
        }
    } catch (error) {
        // if error, set userPendingMembers to empty array
        console.error(error);
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
