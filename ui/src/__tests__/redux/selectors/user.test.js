/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *     http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

import { selectPendingMembersList } from '../../../redux/selectors/domains';

describe('test selectUserPendingMembers', () => {
    it('should return user pending members list', () => {
        let userPendingMembers = {
            'domuser.user2role1': {
                category: 'role',
                domainName: 'dom',
                memberName: 'user.user2',
                memberNameFull: null,
                roleName: 'role1',
                userComment: 'test',
                auditRef: '',
                requestPrincipal: 'user.user3',
                requestPrincipalFull: null,
                requestTime: '2022-07-17T14:37:48.248Z',
                expiryDate: null,
            },
            'domuser.user3role1': {
                category: 'role',
                domainName: 'dom',
                memberName: 'user.user3',
                memberNameFull: null,
                roleName: 'role1',
                userComment: 'test',
                auditRef: '',
                requestPrincipal: 'user.user3',
                requestPrincipalFull: null,
                requestTime: '2022-07-17T14:37:20.725Z',
                expiryDate: null,
            },
            'domuser.user4role1': {
                category: 'role',
                domainName: 'dom',
                memberName: 'user.user4',
                memberNameFull: null,
                roleName: 'role1',
                userComment: 'test',
                auditRef: '',
                requestPrincipal: 'user.user3',
                requestPrincipalFull: null,
                requestTime: '2022-07-17T14:37:34.665Z',
                expiryDate: null,
            },
            'dom.dom2user.user2role2': {
                category: 'role',
                domainName: 'dom.dom2',
                memberName: 'user.user2',
                memberNameFull: null,
                roleName: 'role2',
                userComment: 'added using Athenz UI',
                auditRef: '',
                requestPrincipal: 'user.user1',
                requestPrincipalFull: null,
                requestTime: '2022-07-12T14:29:08.384Z',
                expiryDate: '2022-09-25T14:29:08.374Z',
            },
        };
        const state = {
            user: { pendingMembers: userPendingMembers },
        };
        expect(selectPendingMembersList(state, null, 'admin')).toEqual(
            userPendingMembers
        );
    });
    it('should return empty list', () => {
        const state = {
            user: {},
        };
        expect(selectPendingMembersList(state, null, 'admin')).toEqual([]);
    });
});
