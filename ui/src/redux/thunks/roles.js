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

import API from '../../api';
import { storeRoles } from '../actions/domains';
import {
    addRoleToStore,
    deleteRoleFromStore,
    loadRoles,
    loadRolesToReview,
    marksRoleInStoreAsNeedRefresh,
    returnRoles,
    returnRolesToReview,
    reviewRoleToStore,
} from '../actions/roles';
import {
    checkIfMemberInAllRoles,
    getRoleApiCall,
    getRolesApiCall,
} from './utils/roles';
import {
    thunkSelectRole,
    thunkSelectRoles,
    selectUserReviewRoles,
} from '../selectors/roles';
import {
    buildErrorForDoesntExistCase,
    buildErrorForDuplicateCase,
    getFullName,
    isExpired,
    membersListToMaps,
} from '../utils';
import { roleDelimiter } from '../config';
import {
    addMemberToStore,
    deleteMemberFromStore,
} from '../actions/collections';
import {
    loadingFailed,
    loadingInProcess,
    loadingSuccess,
} from '../actions/loading';

export const addRole =
    (roleName, auditRef, role, _csrf, overrideIfExists = false) =>
    async (dispatch, getState) => {
        roleName = roleName.toLowerCase();
        let domainName = getState().roles.domainName;
        await dispatch(getRoles(domainName));
        let roles = thunkSelectRoles(getState());
        if (
            !overrideIfExists &&
            getFullName(domainName, roleDelimiter, roleName) in roles
        ) {
            return Promise.reject(buildErrorForDuplicateCase('Role', roleName));
        } else {
            try {
                let addedRole = await API().addRole(
                    domainName,
                    roleName,
                    role,
                    auditRef,
                    _csrf,
                    true
                );
                const { members, pendingMembers } = membersListToMaps(
                    addedRole.roleMembers
                );
                addedRole.roleMembers = members;
                addedRole.rolePendingMembers = pendingMembers;
                dispatch(addRoleToStore(addedRole));
                return Promise.resolve();
            } catch (error) {
                return Promise.reject(error);
            }
        }
    };

export const deleteRole =
    (roleName, auditRef, _csrf) => async (dispatch, getState) => {
        roleName = roleName.toLowerCase();
        let domainName = getState().roles.domainName;
        await dispatch(getRoles(domainName));
        let roles = thunkSelectRoles(getState());
        if (!(getFullName(domainName, roleDelimiter, roleName) in roles)) {
            return Promise.reject(
                buildErrorForDoesntExistCase('Role', roleName)
            );
        } else {
            try {
                await API().deleteRole(domainName, roleName, auditRef, _csrf);
                dispatch(
                    deleteRoleFromStore(
                        getFullName(domainName, roleDelimiter, roleName)
                    )
                );
                return Promise.resolve(roleName);
            } catch (error) {
                return Promise.reject(error);
            }
        }
    };

export const marksRoleAsNeedRefresh =
    (domainName, roleName) => async (dispatch, getState) => {
        dispatch(marksRoleInStoreAsNeedRefresh(domainName, roleName));
    };

export const getRole =
    (domainName, roleName, showLoader = true) =>
    async (dispatch, getState) => {
        roleName = roleName.toLowerCase();
        await dispatch(getRoles(domainName));
        let role = thunkSelectRole(getState(), domainName, roleName);
        // auditLog is a unique filed which the backend returns only in getRole api call
        if (role.auditLog && !role.needRefresh) {
            dispatch(returnRoles());
        } else {
            try {
                await getRoleApiCall(
                    domainName,
                    roleName,
                    dispatch,
                    showLoader
                );
                return Promise.resolve();
            } catch (e) {
                return Promise.reject(e);
            }
        }
    };

export const addMemberToRoles =
    (domainName, checkedRoles, member, justification, _csrf) =>
    async (dispatch, getState) => {
        member.memberName = member.memberName.toLowerCase();
        await dispatch(getRoles(domainName));
        if (
            checkIfMemberInAllRoles(
                domainName,
                getState(),
                checkedRoles,
                member.memberName
            )
        ) {
            return Promise.reject({
                statusCode: 409,
                body: {
                    message: `${member.memberName} is already in all roles`,
                },
            });
        } else {
            try {
                let addedMember = await API().addMemberToRoles(
                    domainName,
                    checkedRoles,
                    member.memberName,
                    member,
                    justification,
                    _csrf,
                    true
                );
                for (let member of addedMember) {
                    if (member.approved) {
                        dispatch(
                            addMemberToStore(member, 'role', member.roleName)
                        );
                    }
                }
                return Promise.resolve();
            } catch (error) {
                return Promise.reject(error);
            }
        }
    };

export const getRoles = (domainName) => async (dispatch, getState) => {
    if (getState().roles.expiry) {
        if (getState().roles.domainName !== domainName) {
            dispatch(storeRoles(getState().roles));
            if (
                getState().domains[domainName] &&
                getState().domains[domainName].roles &&
                !isExpired(getState().domains[domainName].roles.expiry)
            ) {
                dispatch(
                    loadRoles(
                        getState().domains[domainName].roles.roles,
                        domainName,
                        getState().domains[domainName].roles.expiry
                    )
                );
            } else {
                await getRolesApiCall(domainName, dispatch);
            }
        } else if (isExpired(getState().roles.expiry)) {
            await getRolesApiCall(domainName, dispatch);
        } else {
            dispatch(returnRoles());
        }
    } else {
        await getRolesApiCall(domainName, dispatch);
    }
};

export const reviewRole =
    (domainName, role, justification, _csrf) => async (dispatch, getState) => {
        role.name = role.name.toLowerCase();
        await dispatch(getRole(domainName, role.name));
        try {
            let reviewedRole = await API().reviewRole(
                domainName,
                role.name,
                role,
                justification,
                _csrf,
                true
            );
            const { members, pendingMembers } = membersListToMaps(
                reviewedRole.roleMembers
            );
            reviewedRole.roleMembers = members;
            reviewedRole.rolePendingMembers = pendingMembers;

            dispatch(reviewRoleToStore(reviewedRole.name, reviewedRole));
            let rolesToReview = selectUserReviewRoles(getState());
            rolesToReview = rolesToReview.filter(
                (r) => r.domainName + ':role.' + r.name !== reviewedRole.name
            );
            if (
                rolesToReview.length !==
                selectUserReviewRoles(getState()).length
            ) {
                dispatch(loadRolesToReview(rolesToReview));
            }
            dispatch(marksRoleAsNeedRefresh(domainName, role.name));
            return Promise.resolve();
        } catch (error) {
            return Promise.reject(error);
        }
    };

export const deleteMemberFromAllRoles =
    (domainName, deleteName, auditRef, _csrf) => async (dispatch, getState) => {
        try {
            await API().deleteRoleMember(
                domainName,
                deleteName,
                auditRef,
                _csrf
            );
            let roles = thunkSelectRoles(getState());
            for (let [roleName, role] of Object.entries(roles)) {
                if (deleteName in role.roleMembers) {
                    dispatch(
                        deleteMemberFromStore(deleteName, 'role', roleName)
                    );
                }
            }
            return Promise.resolve();
        } catch (error) {
            return Promise.reject(error);
        }
    };

export const getRoleHistory =
    (domainName, roleName) => async (dispatch, getState) => {
        try {
            await getRoleApiCall(domainName, roleName, dispatch);
        } catch (error) {
            return Promise.reject(error);
        }
    };

export const getReviewRoles = () => async (dispatch, getState) => {
    try {
        if (!getState().roles.rolesToReview) {
            dispatch(loadingInProcess('getReviewRoles'));
            const reviewRoles = await API().getReviewRoles();
            dispatch(loadRolesToReview(reviewRoles));
            dispatch(loadingSuccess('getReviewRoles'));
        } else {
            dispatch(returnRolesToReview());
        }
    } catch (error) {
        // if error, set rolesToReview to empty array
        dispatch(loadRolesToReview([]));
        dispatch(loadingFailed('getReviewRoles'));
        throw error;
    }
};
