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
    returnRoles,
    reviewRoleToStore,
} from '../actions/roles';
import {
    checkIfMemberInAllRoles,
    getRoleApiCall,
    getRolesApiCall,
} from './utils/roles';
import { thunkSelectRole, thunkSelectRoles } from '../selectors/roles';
import {
    buildErrorForDoesntExistCase,
    buildErrorForDuplicateCase,
    getCurrentTime,
    getFullName,
    isExpired,
    listToMap,
} from '../utils';
import { roleDelimiter } from '../config';
import {
    addMemberToStore,
    deleteMemberFromStore,
} from '../actions/collections';

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
                addedRole.roleMembers = listToMap(
                    addedRole.roleMembers,
                    'memberName'
                );
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

export const getRole =
    (domainName, roleName) => async (dispatch, getState) => {
        roleName = roleName.toLowerCase();
        await dispatch(getRoles(domainName));
        let role = thunkSelectRole(getState(), domainName, roleName);
        // auditLog is a unique filed which the backend returns only in getRole api call
        if (role.auditLog) {
            dispatch(returnRoles());
        } else {
            try {
                await getRoleApiCall(domainName, roleName, dispatch);
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
            reviewedRole.roleMembers = listToMap(
                reviewedRole.roleMembers,
                'memberName'
            );

            dispatch(reviewRoleToStore(reviewedRole.name, reviewedRole));
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
