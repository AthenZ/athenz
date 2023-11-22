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
import React from 'react';
import { waitFor } from '@testing-library/react';
import SettingPage from '../../../../../../pages/domain/[domain]/role/[role]/settings';
import {
    mockAllDomainDataApiCalls,
    mockRolesApiCalls,
    renderWithRedux,
} from '../../../../../../tests_utils/ComponentsTestUtils';
import MockApi from '../../../../../../mock/MockApi';
import Api from '../../../../../../api';

const selectorsRoles = require('../../../../../../redux/selectors/roles');
const selectorsDomainData = require('../../../../../../redux/selectors/domainData');
const selectorsDomains = require('../../../../../../redux/selectors/domains');
const selectorsLoading = require('../../../../../../redux/selectors/loading');
const thunkRoles = require('../../../../../../redux/thunks/roles');
const thunkGroups = require('../../../../../../redux/thunks/groups');
const thunkDomainData = require('../../../../../../redux/thunks/domain');
const thunkDomains = require('../../../../../../redux/thunks/domains');
const thunkUser = require('../../../../../../redux/thunks/user');

describe('SettingPage', () => {
    afterEach(() => {
        MockApi.cleanMockApi();
    });
    it('should render', async () => {
        let domainName = 'dom';
        let role = 'roleName';
        let domains = [];
        domains.push({ name: 'athens' });
        domains.push({ name: 'athens.ci' });
        let query = {
            domain: 'dom',
        };
        let roleDetails = {
            name: domainName + ':role.' + role,
            modified: '2020-02-12T21:44:37.792Z',
        };
        let headerDetails = {
            headerLinks: [
                {
                    title: 'Website',
                    url: 'http://www.athenz.io',
                    target: '_blank',
                },
            ],
            userData: {
                userLink: {
                    title: 'User Link',
                    url: '',
                    target: '_blank',
                },
            },
        };
        jest.spyOn(thunkDomainData, 'getDomainData').mockReturnValue({
            type: 'mock',
        });
        jest.spyOn(thunkRoles, 'getRole').mockReturnValue({ type: 'mock' });
        jest.spyOn(thunkUser, 'getUserPendingMembers').mockReturnValue({
            type: 'mock',
        });
        jest.spyOn(thunkDomains, 'getUserDomainsList').mockReturnValue({
            type: 'mock',
        });
        jest.spyOn(thunkRoles, 'getReviewRoles').mockReturnValue({
            type: 'mock',
        });
        jest.spyOn(thunkGroups, 'getReviewGroups').mockReturnValue({
            type: 'mock',
        });
        let domainDetails = {
            modified: '2020-02-12T21:44:37.792Z',
        };
        const mockApi = {
            ...mockAllDomainDataApiCalls(domainDetails, headerDetails),
            getPageFeatureFlag: jest.fn().mockResolvedValue({}),
        };
        MockApi.setMockApi(mockApi);

        jest.spyOn(selectorsRoles, 'selectRole').mockReturnValue(roleDetails);
        jest.spyOn(selectorsRoles, 'selectUserReviewRoles').mockReturnValue([]);
        jest.spyOn(selectorsLoading, 'selectIsLoading').mockReturnValue([]);
        jest.spyOn(selectorsDomains, 'selectHeaderDetails').mockReturnValue(
            headerDetails
        );
        jest.spyOn(
            selectorsDomainData,
            'selectDomainAuditEnabled'
        ).mockReturnValue(undefined);
        jest.spyOn(selectorsDomains, 'selectUserDomains').mockReturnValue(
            domains
        );

        const { getByTestId } = renderWithRedux(
            <SettingPage
                req='req'
                userId='userid'
                query={query}
                reload={false}
                roleName={role}
                domainName={domainName}
            />
        );
        const settingPage = getByTestId('setting');
        expect(settingPage).toMatchSnapshot();
    });
});

// describe('SettingPage integration', () => {
//     afterEach(() => {
//         MockApi.cleanMockApi();
//     })
//     it('should render', async () => {
//         let domainName = 'dom';
//         let role = 'roleName';
//         let domains = [];
//         domains.push({ name: 'athens' });
//         domains.push({ name: 'athens.ci' });
//         let query = {
//             domain: 'dom',
//         };
//         let domainDetails = {
//             modified: '2020-02-12T21:44:37.792Z',
//         };
//         let roleDetails = {
//             name: domainName + ':role.' + role,
//             modified: '2020-02-12T21:44:37.792Z',
//         };
//         let headerDetails = {
//             headerLinks: [
//                 {
//                     title: 'Website',
//                     url: 'http://www.athenz.io',
//                     target: '_blank',
//                 },
//             ],
//             userData: {
//                 userLink: {
//                     title: 'User Link',
//                     url: '',
//                     target: '_blank',
//                 },
//             },
//         };
//         const mockApi = {
//             ...mockAllDomainDataApiCalls(domainDetails, headerDetails),
//             ...mockRolesApiCalls(),
//             getPendingDomainMembersList: jest.fn().mockReturnValue(
//                 new Promise((resolve, reject) => {
//                     resolve([]);
//                 })
//             ),
//             getRole: jest.fn().mockReturnValue(Promise.resolve(roleDetails)),
//             listUserDomains: jest.fn().mockReturnValue(
//                 Promise.resolve(domains)
//             ),
//         }
//         MockApi.setMockApi(mockApi);
//
//         const { getByTestId } = renderWithRedux(
//             <SettingPage
//                 req='req'
//                 userId='userid'
//                 query={query}
//                 reload={false}
//                 roleName={role}
//                 domainName={domainName}
//             />
//         );
//         await waitFor(() => expect(getByTestId('setting')).toBeInTheDocument());
//         const settingPage = getByTestId('setting');
//         expect(settingPage).toMatchSnapshot();
//     });
// });
