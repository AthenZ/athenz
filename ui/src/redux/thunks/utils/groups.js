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
import { loadGroup, loadGroups } from '../../actions/groups';
import API from '../../../api';
import {
    getExpiryTime,
    getFullName,
    listToMap,
    membersListToMaps,
} from '../../utils';
import { groupDelimiter } from '../../config';

export const getGroupsApiCall = async (domainName, dispatch) => {
    dispatch(loadingInProcess('getGroups'));
    try {
        const groupList = await API().getGroups(domainName, true);
        const expiry = getExpiryTime();
        groupList.forEach((group) => {
            group.expiry = expiry;
            group.groupMembers = listToMap(group.groupMembers, 'memberName');
        });
        let groupsMap = listToMap(groupList, 'name');
        dispatch(loadGroups(groupsMap, domainName, expiry));
        dispatch(loadingSuccess('getGroups'));
    } catch (e) {
        dispatch(loadingFailed('getGroups'));
        throw e;
    }
};

export const getGroupApiCall = async (domainName, groupName, dispatch) => {
    try {
        dispatch(loadingInProcess('getGroup'));
        let group = await API().getGroup(domainName, groupName, true, true);
        let currRoleMembers = await API().getDomainRoleMembers(
            getFullName(domainName, groupDelimiter, groupName)
        );
        // This is done to avoid retrieving it from the server again if getGroup is called again
        if (!group.auditLog) {
            group.auditLog = [];
        }
        group.roleMembers = currRoleMembers;
        const { members, pendingMembers } = membersListToMaps(
            group.groupMembers
        );
        group.groupMembers = members;
        group.groupPendingMembers = pendingMembers;
        dispatch(
            loadGroup(group, getFullName(domainName, groupDelimiter, groupName))
        );
        dispatch(loadingSuccess('getGroup'));
    } catch (err) {
        dispatch(loadingFailed('getGroup'));
        throw err;
    }
};
