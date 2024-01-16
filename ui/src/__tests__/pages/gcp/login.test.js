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
import { renderWithRedux } from '../../../tests_utils/ComponentsTestUtils';
import GCPLoginPage from '../../../pages/gcp/login';
import MockApi from '../../../mock/MockApi';

afterEach(() => {
    MockApi.cleanMockApi();
});

describe('GCP Login Page', () => {
    it('should render error no gcp project when api returns no results', async () => {
        const mockApi = {
            getResourceAccessList: jest.fn().mockReturnValue([]),
        };
        MockApi.setMockApi(mockApi);
        const { getByTestId } = renderWithRedux(<GCPLoginPage />, {
            isFetching: false,
        });
        await waitFor(() =>
            expect(getByTestId('gcp-login-error')).toMatchSnapshot()
        );
    });

    it('should render projects api returns results', async () => {
        let testData = {
            resources: [
                {
                    assertions: [
                        {
                            role: 'dummy.project:role.user.dev',
                            resource:
                                'projects/dummy-project-id/roles/dummy.role',
                        },
                    ],
                },
            ],
        };
        const mockApi = {
            getResourceAccessList: jest
                .fn()
                .mockReturnValue(Promise.resolve(testData)),
        };
        MockApi.setMockApi(mockApi);
        const { getByTestId } = renderWithRedux(<GCPLoginPage
            userAuthority='dev'
         />);
        await waitFor(() => expect(getByTestId('gcp-login')).toMatchSnapshot());
    });
});
