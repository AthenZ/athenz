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
import { fireEvent, waitFor, screen } from '@testing-library/react';
import SelfServiceView from '../../../components/self-service/SelfServiceView';
import { renderWithRedux } from '../../../tests_utils/ComponentsTestUtils';
import MockApi from '../../../mock/MockApi';

// flatpickr date selection is not reliable in jsdom, so we stub the extend
// modal with a button that fires onSubmit directly. This lets us verify how
// the view maps the ZMS response (the membership's `approved` flag) onto the
// success message without driving a real date picker.
jest.mock(
    '../../../components/self-service/ExtendMembershipModal',
    () => (props) =>
        require('react').createElement(
            'button',
            {
                'data-testid': 'mock-extend-submit',
                onClick: () => props.onSubmit('2026-12-31T00:00:00.000Z'),
            },
            'submit-extend'
        )
);

const membershipsWith = () => ({
    list: [
        {
            type: 'role',
            domainName: 'paranoids.tools',
            name: 'scanner-admins',
            description: 'Admin access to scans.',
            memberStatus: 'member',
            selfRenew: true,
            maxExpiryDays: 30,
            expiration: '2026-12-30T00:00:00.000Z',
        },
    ],
    domains: ['paranoids.tools'],
    membershipCount: 1,
});

const setupApi = (updateResult) => {
    MockApi.setMockApi({
        getPendingDomainMembersList: jest.fn().mockResolvedValue([]),
        getReviewGroups: jest.fn().mockReturnValue([]),
        getReviewRoles: jest.fn().mockReturnValue([]),
        getPageFeatureFlag: jest.fn().mockResolvedValue({}),
        searchSelfServe: jest
            .fn()
            .mockImplementation((matchString, domain, member) =>
                member
                    ? Promise.resolve(membershipsWith())
                    : Promise.resolve({
                          list: [],
                          domains: ['paranoids.tools'],
                          membershipCount: 1,
                      })
            ),
        updateSelfServe: jest.fn().mockResolvedValue(updateResult),
    });
};

const openExtendAndSubmit = async () => {
    renderWithRedux(<SelfServiceView userName='tsultanov' _csrf='csrf' />);
    fireEvent.click(await screen.findByText(/My Roles & Groups \(1\)/));
    await waitFor(() =>
        expect(screen.getByText('scanner-admins')).toBeInTheDocument()
    );
    fireEvent.click(
        screen.getByTestId('extend-paranoids.tools:role.scanner-admins')
    );
    fireEvent.click(await screen.findByTestId('mock-extend-submit'));
};

describe('SelfServiceView extend outcome message', () => {
    afterEach(() => {
        MockApi.cleanMockApi();
    });

    it('shows "Membership extended" when ZMS applies the change (approved=true)', async () => {
        setupApi({ approved: true });
        await openExtendAndSubmit();
        expect(
            await screen.findByText('Membership extended')
        ).toBeInTheDocument();
    });

    it('shows "Request submitted" when ZMS queues the change (approved=false)', async () => {
        setupApi({ approved: false });
        await openExtendAndSubmit();
        expect(
            await screen.findByText('Request submitted')
        ).toBeInTheDocument();
    });

    it('shows a neutral message when ZMS returns no body', async () => {
        setupApi({});
        await openExtendAndSubmit();
        expect(
            await screen.findByText('Extension submitted')
        ).toBeInTheDocument();
    });
});
