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
    addGroupToStore,
    deleteGroupFromStore,
    loadGroups,
    loadGroupsToReview,
    returnGroups,
    returnGroupsToReview,
    reviewGroupToStore,
} from '../actions/groups';
import API from '../../api';
import { storeGroups } from '../actions/domains';
import { getGroupApiCall, getGroupsApiCall } from './utils/groups';
import {
    selectUserReviewGroups,
    thunkSelectGroup,
    thunkSelectGroups,
} from '../selectors/groups';
import {
    buildErrorForDoesntExistCase,
    buildErrorForDuplicateCase,
    getFullName,
    isExpired,
    listToMap,
    membersListToMaps,
} from '../utils';
import { groupDelimiter, memberNameKey } from '../config';
import { getRoleApiCall } from './utils/roles';
import {
    loadingFailed,
    loadingInProcess,
    loadingSuccess,
} from '../actions/loading';

export const addGroup =
    (groupName, auditRef, group, _csrf) => async (dispatch, getState) => {
        groupName = groupName.toLowerCase();
        let domainName = getState().groups.domainName;
        await dispatch(getGroups(domainName));
        let groupsMap = thunkSelectGroups(getState());
        if (getFullName(domainName, groupDelimiter, groupName) in groupsMap) {
            return Promise.reject(
                buildErrorForDuplicateCase('Group', groupName)
            );
        } else {
            try {
                let addedGroup = await API().addGroup(
                    domainName,
                    groupName,
                    group,
                    auditRef,
                    _csrf,
                    true
                );
                const { members, pendingMembers } = membersListToMaps(
                    addedGroup.groupMembers,
                    memberNameKey
                );
                addedGroup.groupMembers = members;
                addedGroup.groupPendingMembers = pendingMembers;

                dispatch(addGroupToStore(addedGroup));
                return Promise.resolve();
            } catch (err) {
                return Promise.reject(err);
            }
        }
    };

export const deleteGroup =
    (groupName, auditRef, _csrf) => async (dispatch, getState) => {
        groupName = groupName.toLowerCase();
        let domainName = getState().groups.domainName;
        await dispatch(getGroups(domainName));
        let groupsMap = thunkSelectGroups(getState());
        if (
            !(getFullName(domainName, groupDelimiter, groupName) in groupsMap)
        ) {
            return Promise.reject(
                buildErrorForDoesntExistCase('Group', groupName)
            );
        } else {
            try {
                await API().deleteGroup(domainName, groupName, auditRef, _csrf);
                dispatch(
                    deleteGroupFromStore(
                        getFullName(domainName, groupDelimiter, groupName)
                    )
                );
                return Promise.resolve();
            } catch (err) {
                return Promise.reject(err);
            }
        }
    };

export const reviewGroup =
    (groupName, group, justification, _csrf) => async (dispatch, getState) => {
        groupName = groupName.toLowerCase();
        let domainName = getState().groups.domainName;
        await dispatch(getGroup(domainName, groupName));
        try {
            let reviewedGroup = await API().reviewGroup(
                domainName,
                groupName,
                group,
                justification,
                _csrf,
                true
            );
            const { members, pendingMembers } = membersListToMaps(
                reviewedGroup.groupMembers,
                memberNameKey
            );
            reviewedGroup.groupMembers = members;
            reviewedGroup.groupPendingMembers = pendingMembers;
            let groupsToReview = selectUserReviewGroups(getState());
            groupsToReview = groupsToReview.filter(
                (g) => g.domainName + ':group.' + g.name !== reviewedGroup.name
            );
            if (
                selectUserReviewGroups(getState()).length !==
                groupsToReview.length
            ) {
                dispatch(loadGroupsToReview(groupsToReview));
            }
            dispatch(reviewGroupToStore(reviewedGroup.name, reviewedGroup));
            return Promise.resolve();
        } catch (err) {
            return Promise.reject(err);
        }
    };

export const getGroup =
    (domainName, groupName) => async (dispatch, getState) => {
        try {
            groupName = groupName.toLowerCase();
            await dispatch(getGroups(domainName));
            let group = thunkSelectGroup(getState(), domainName, groupName);
            if (group.auditLog) {
                dispatch(returnGroups());
            } else {
                await getGroupApiCall(domainName, groupName, dispatch);
            }
        } catch (err) {
            throw err;
        }
    };

export const getGroups = (domainName) => async (dispatch, getState) => {
    let groups = getState().groups;
    if (groups.expiry) {
        if (groups.domainName !== domainName) {
            dispatch(storeGroups(groups));
            if (
                getState().domains[domainName] &&
                getState().domains[domainName].groups &&
                !isExpired(getState().domains[domainName].groups.expiry)
            ) {
                dispatch(
                    loadGroups(
                        getState().domains[domainName].groups.groups,
                        domainName,
                        getState().domains[domainName].groups.expiry
                    )
                );
            } else {
                await getGroupsApiCall(domainName, dispatch);
            }
        } else if (isExpired(groups.expiry)) {
            await getGroupsApiCall(domainName, dispatch);
        } else {
            dispatch(returnGroups());
        }
    } else {
        await getGroupsApiCall(domainName, dispatch);
    }
};

export const getGroupHistory =
    (domainName, groupName) => async (dispatch, getState) => {
        try {
            await getGroupApiCall(domainName, groupName, dispatch);
        } catch (error) {
            return Promise.reject(error);
        }
    };

export const getReviewGroups = () => async (dispatch, getState) => {
    try {
        if (!getState().groups.groupsToReview) {
            dispatch(loadingInProcess('getReviewGroups'));
            const reviewGroups = await API().getReviewGroups();
            dispatch(loadGroupsToReview(reviewGroups));
            dispatch(loadingSuccess('getReviewGroups'));
        } else {
            dispatch(returnGroupsToReview());
        }
    } catch (error) {
        // if error, set groupsToReview to empty array
        dispatch(loadGroupsToReview([]));
        dispatch(loadingFailed('getReviewGroups'));
        throw error;
    }
};
