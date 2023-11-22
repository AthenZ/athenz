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

import { thunkSelectGroup, thunkSelectGroupMember } from '../selectors/groups';
import { getGroup } from './groups';
import { getRole, marksRoleAsNeedRefresh } from './roles';
import { thunkSelectRole, thunkSelectRoleMember } from '../selectors/roles';
import {
    addMemberToStore,
    addPendingMemberToStore,
    deleteMemberFromStore,
    deletePendingMemberFromStore,
    updateSettingsToStore,
    updateTagsToStore,
} from '../actions/collections';
import API from '../../api';
import { buildMembersMapName, getFullCollectionName } from './utils/collection';
import {
    buildErrorForDoesntExistCase,
    buildErrorForDuplicateCase,
} from '../utils';
import { getRoleApiCall } from './utils/roles';
import { updateBellPendingMember } from '../actions/domain-data';
import { groupDelimiter } from '../config';
import { PENDING_STATE_ENUM } from '../../components/constants/constants';

export const editMember =
    (domainName, collectionName, category, member, auditRef, _csrf) =>
    async (dispatch, getState) => {
        collectionName = collectionName.toLowerCase();
        // before we call to addMember endpoint we must replace the member role/group name to a short name
        switch (category) {
            case 'role':
                member.roleName = collectionName;
                break;
            case 'group':
                member.groupName = collectionName;
        }

        await dispatch(
            addMember(
                domainName,
                collectionName,
                category,
                member,
                auditRef,
                _csrf,
                true
            )
        );
    };

export const addMember =
    (
        domainName,
        collectionName,
        category,
        member,
        auditRef,
        _csrf,
        overrideIfExists = false
    ) =>
    async (dispatch, getState) => {
        collectionName = collectionName.toLowerCase();
        let data = {};
        if (category === 'group') {
            data = thunkSelectGroup(getState(), domainName, collectionName);
        } else if (category === 'role') {
            if (
                member.memberName.includes(groupDelimiter) &&
                collectionName === 'admin'
            ) {
                return Promise.reject({
                    body: {
                        message:
                            'Group principals are not allowed in the admin role',
                    },
                    statusCode: 400,
                });
            }
            await dispatch(getRole(domainName, collectionName));
            data = thunkSelectRole(getState(), domainName, collectionName);
        }
        if (
            !overrideIfExists &&
            member.memberName in
                data[buildMembersMapName(category, member.pending)]
        ) {
            return Promise.reject(
                buildErrorForDuplicateCase('Member', member.memberName)
            );
        } else {
            try {
                let addedMember = await API().addMember(
                    domainName,
                    collectionName,
                    member.memberName,
                    member,
                    auditRef,
                    category,
                    _csrf,
                    true
                );
                // if the member is a group we need to call getRole in order to get the group members and display it
                if (member.memberName.toLowerCase().includes(':group.')) {
                    await getRoleApiCall(domainName, collectionName, dispatch);
                } else {
                    if (!addedMember.approved) {
                        dispatch(
                            addPendingMemberToStore(
                                addedMember,
                                category,
                                getFullCollectionName(
                                    domainName,
                                    collectionName,
                                    category
                                )
                            )
                        );
                        dispatch(
                            updateBellPendingMember(
                                member.memberName,
                                getFullCollectionName(
                                    domainName,
                                    collectionName,
                                    category
                                )
                            )
                        );
                    } else {
                        dispatch(
                            addMemberToStore(
                                addedMember,
                                category,
                                getFullCollectionName(
                                    domainName,
                                    collectionName,
                                    category
                                )
                            )
                        );
                    }
                }
                return Promise.resolve();
            } catch (err) {
                return Promise.reject(err);
            }
        }
    };

const handlePendingMemberDeleted = (
    dispatch,
    memberName,
    category,
    domainName,
    collectionName
) => {
    dispatch(
        deletePendingMemberFromStore(
            memberName,
            category,
            getFullCollectionName(domainName, collectionName, category)
        )
    );
    dispatch(
        updateBellPendingMember(
            memberName,
            getFullCollectionName(domainName, collectionName, category)
        )
    );
    return Promise.resolve();
};

const handleMemberDeletedFromProtectedCollection = (
    state,
    memberName,
    collectionName,
    dispatch,
    category,
    domainName
) => {
    let memberFullName =
        category === 'role'
            ? thunkSelectRoleMember(
                  state,
                  domainName,
                  collectionName,
                  memberName
              )['memberFullName']
            : thunkSelectGroupMember(
                  state,
                  domainName,
                  collectionName,
                  memberName
              )['memberFullName'];
    let member = {
        memberName: memberName,
        memberFullName: memberFullName,
        pendingState: PENDING_STATE_ENUM.DELETE,
        [category === 'role' ? 'roleName' : 'groupName']: collectionName,
        active: false,
        approved: false,
    };
    dispatch(
        addPendingMemberToStore(
            member,
            category,
            getFullCollectionName(domainName, collectionName, category)
        )
    );
    dispatch(
        updateBellPendingMember(
            memberName,
            getFullCollectionName(domainName, collectionName, category)
        )
    );
    return Promise.resolve(true);
};

export const deleteMember =
    (
        domainName,
        collectionName,
        category,
        memberName,
        auditRef,
        pending,
        _csrf
    ) =>
    async (dispatch, getState) => {
        collectionName = collectionName.toLowerCase();
        let data = {};
        if (category === 'group') {
            await dispatch(getGroup(domainName, collectionName));
            data = thunkSelectGroup(getState(), domainName, collectionName);
        } else if (category === 'role') {
            await dispatch(getRole(domainName, collectionName));
            data = thunkSelectRole(getState(), domainName, collectionName);
        }

        if (memberName in data[buildMembersMapName(category, pending)]) {
            try {
                await API().deleteMember(
                    domainName,
                    collectionName,
                    memberName,
                    auditRef,
                    pending,
                    category,
                    _csrf
                );
                if (
                    data[buildMembersMapName(category, pending)][memberName]
                        .approved === false
                ) {
                    return handlePendingMemberDeleted(
                        dispatch,
                        memberName,
                        category,
                        domainName,
                        collectionName
                    );
                } else {
                    if (
                        (category === 'role' || category === 'group') &&
                        data.deleteProtection &&
                        (data.auditEnabled || data.reviewEnabled)
                    ) {
                        return handleMemberDeletedFromProtectedCollection(
                            getState(),
                            memberName,
                            collectionName,
                            dispatch,
                            category,
                            domainName
                        );
                    } else {
                        dispatch(
                            deleteMemberFromStore(
                                memberName,
                                category,
                                getFullCollectionName(
                                    domainName,
                                    collectionName,
                                    category
                                )
                            )
                        );
                    }
                }
                return Promise.resolve();
            } catch (err) {
                return Promise.reject(err);
            }
        } else {
            return Promise.reject(
                buildErrorForDoesntExistCase('Member', memberName)
            );
        }
    };

export const updateTags =
    (domain, collectionName, detail, auditRef, _csrf, category) =>
    async (dispatch, getState) => {
        try {
            collectionName = collectionName.toLowerCase();
            await API().putMeta(
                domain,
                collectionName,
                detail,
                auditRef,
                _csrf,
                category
            );
            dispatch(
                updateTagsToStore(
                    getFullCollectionName(domain, collectionName, category),
                    detail,
                    category
                )
            );
            return Promise.resolve();
        } catch (err) {
            return Promise.reject(err);
        }
    };

export const marksCollectionAsNeedRefresh =
    (domainName, category, collectionName) => async (dispatch, getStore) => {
        switch (category) {
            case 'role':
                dispatch(marksRoleAsNeedRefresh(domainName, collectionName));
        }
    };
export const updateSettings =
    (domainName, collectionMeta, collectionName, _csrf, category) =>
    async (dispatch, getStore) => {
        try {
            collectionName = collectionName.toLowerCase();
            await API().putMeta(
                domainName,
                collectionName,
                collectionMeta,
                'Updated domain Meta using Athenz UI',
                _csrf,
                category
            );
            dispatch(
                updateSettingsToStore(
                    getFullCollectionName(domainName, collectionName, category),
                    collectionMeta,
                    category
                )
            );
            dispatch(
                marksCollectionAsNeedRefresh(
                    domainName,
                    category,
                    collectionName
                )
            );
            return Promise.resolve();
        } catch (err) {
            return Promise.reject(err);
        }
    };
