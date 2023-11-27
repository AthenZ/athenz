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

export const LOAD_ROLES = 'LOAD_ROLES';
export const loadRoles = (roles, domainName, expiry) => ({
    type: LOAD_ROLES,
    payload: { roles: roles, domainName: domainName, expiry: expiry },
});

export const RETURN_ROLES = 'RETURN_ROLES';
export const returnRoles = () => ({
    type: RETURN_ROLES,
});

export const LOAD_ROLES_TO_REVIEW = 'LOAD_ROLES_TO_REVIEW';
export const loadRolesToReview = (rolesToReview) => ({
    type: LOAD_ROLES_TO_REVIEW,
    payload: { rolesToReview: rolesToReview },
});

export const RETURN_ROLES_TO_REVIEW = 'RETURN_ROLES_TO_REVIEW';
export const returnRolesToReview = () => ({
    type: RETURN_ROLES_TO_REVIEW,
});

export const ADD_ROLE_TO_STORE = 'ADD_ROLE_TO_STORE';
export const addRoleToStore = (roleData) => ({
    type: ADD_ROLE_TO_STORE,
    payload: {
        roleData: roleData,
    },
});

export const DELETE_ROLE_FROM_STORE = 'DELETE_ROLE_FROM_STORE';
export const deleteRoleFromStore = (roleName) => ({
    type: DELETE_ROLE_FROM_STORE,
    payload: {
        roleName: roleName,
    },
});
export const LOAD_ROLE = 'LOAD_ROLE';
export const loadRole = (roleData, roleName) => ({
    type: LOAD_ROLE,
    payload: {
        roleData: roleData,
        roleName: roleName,
    },
});
export const REVIEW_ROLE = 'REVIEW_ROLE';
export const reviewRoleToStore = (roleName, reviewedRole) => ({
    type: REVIEW_ROLE,
    payload: {
        roleName,
        reviewedRole,
    },
});

export const MAKE_ROLES_EXPIRES = 'MAKE_ROLES_EXPIRES';
export const makeRolesExpires = () => ({
    type: MAKE_ROLES_EXPIRES,
});

export const MARKS_ROLE_AS_NEED_REFRESH = 'MARKS_ROLE_AS_NEED_REFRESH';
export const marksRoleInStoreAsNeedRefresh = (domainName, roleName) => ({
    type: MARKS_ROLE_AS_NEED_REFRESH,
    payload: {
        domainName,
        roleName,
        needRefresh: true,
    },
});
