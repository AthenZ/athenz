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

import {
    loadingFailed,
    loadingInProcess,
    loadingSuccess,
} from '../../actions/loading';
import { loadRole, loadRoles } from '../../actions/roles';
import {
    getExpiryTime,
    getFullName,
    listToMap,
    membersListToMaps,
} from '../../utils';
import API from '../../../api';
import { roleDelimiter } from '../../config';
import { thunkSelectRoleMembers } from '../../selectors/roles';
import AppUtils from '../../../components/utils/AppUtils';

export const prepareRoleMembers = (roleMap) => {
    let membersToRole = {};
    for (const [roleName, role] of Object.entries(roleMap)) {
        for (const [memberName, member] of Object.entries(role.roleMembers)) {
            if (!(memberName in membersToRole)) {
                membersToRole[memberName] = [];
            }
            membersToRole[memberName].push(roleName);
        }
    }
    return membersToRole;
};

export const mergeUserListWithRoleListData = (roleMap, userMap) => {
    let membersToRole = prepareRoleMembers(roleMap);
    let returnRoleMap = AppUtils.deepClone(roleMap);
    for (const [memberName, member] of Object.entries(userMap)) {
        if (memberName in membersToRole) {
            for (const roleName of membersToRole[memberName]) {
                returnRoleMap[roleName].roleMembers[memberName].memberFullName =
                    member.memberFullName;
            }
        }
    }
    return returnRoleMap;
};

export const getRolesApiCall = async (domainName, dispatch) => {
    dispatch(loadingInProcess('getRoles'));
    try {
        // the role page has 2 tabs role and users and for making those 2 pages using a single source of truth
        // we combine the data from the 2 api calls into one object holds in the store
        let [roleList, userList] = await Promise.all([
            API().getRoles(domainName, true),
            API().getRoleMembers(domainName),
        ]);
        const expiry = getExpiryTime();
        roleList.forEach((role) => {
            const { members, pendingMembers } = membersListToMaps(
                role.roleMembers
            );
            role.roleMembers = members;
            role.rolePendingMembers = pendingMembers;
        });
        let rolesMap = listToMap(roleList, 'name');
        rolesMap = mergeUserListWithRoleListData(
            rolesMap,
            listToMap(userList.members, 'memberName')
        );
        dispatch(loadRoles(rolesMap, domainName, expiry));
        dispatch(loadingSuccess('getRoles'));
    } catch (e) {
        dispatch(loadingFailed('getRoles'));
        throw e;
    }
};

// note: if showLoader is true it will show the loader page while the api call is in progress
export const getRoleApiCall = async (
    domainName,
    roleName,
    dispatch,
    showLoader = true
) => {
    if (showLoader) {
        dispatch(loadingInProcess('getRole'));
    }
    try {
        roleName = roleName.toLowerCase();
        let role = await API().getRole(domainName, roleName, true, false, true);
        // This is done to avoid retrieving it from the server again if getRole is called again
        if (!role.auditLog) {
            role.auditLog = [];
        }
        const { members, pendingMembers } = membersListToMaps(role.roleMembers);
        role.roleMembers = members;
        role.rolePendingMembers = pendingMembers;
        dispatch(
            loadRole(role, getFullName(domainName, roleDelimiter, roleName))
        );
    } catch (e) {
        throw e;
    } finally {
        if (showLoader) {
            dispatch(loadingSuccess('getRole'));
        }
    }
};

export const checkIfMemberInAllRoles = (
    domainName,
    state,
    roleList,
    memberName
) => {
    let checkedMemberInAllRoles = true;
    for (let roleName of roleList) {
        roleName = roleName.toLowerCase();
        let roleMembers = thunkSelectRoleMembers(state, domainName, roleName);
        if (!(memberName in roleMembers)) {
            checkedMemberInAllRoles = false;
            break;
        }
    }
    return checkedMemberInAllRoles;
};
