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
import { screen, waitFor } from '@testing-library/react';
import SettingTable from '../../../components/settings/SettingTable';
import {
    buildDomainDataForState,
    getStateWithDomainData,
    renderWithRedux,
} from '../../../tests_utils/ComponentsTestUtils';

describe('SettingTable', () => {
    it('should render setting table', () => {
        let domain = 'domain';
        let role = 'roleName';
        const roleDetails = {
            reviewEnabled: true,
            selfServe: false,
            memberExpiryDays: 3,
            serviceExpiryDays: 3,
            tokenExpiryMins: 15,
            certExpiryMins: 15,
        };

        const { getByTestId } = renderWithRedux(
            <SettingTable
                category={'role'}
                domain={domain}
                collection={role}
                collectionDetails={roleDetails}
                userAuthorityAttributes={[]}
            />
        );
        const settingTable = getByTestId('setting-table');

        expect(settingTable).toMatchSnapshot();
    });

    it('should render setting table for audit enabled domain', () => {
        let domain = 'domain';
        const domainMetadata = {
            modified: '2020-02-12T21:44:37.792Z',
            auditEnabled: true,
        };
        const domainData = buildDomainDataForState(domainMetadata, domain);
        let role = 'roleName';
        const roleDetails = {
            reviewEnabled: true,
            auditEnabled: true,
            selfServe: false,
            memberExpiryDays: 3,
            serviceExpiryDays: 3,
            tokenExpiryMins: 15,
            certExpiryMins: 15,
        };

        const { getByTestId } = renderWithRedux(
            <SettingTable
                category={'role'}
                domain={domain}
                collection={role}
                collectionDetails={roleDetails}
                userAuthorityAttributes={[]}
            />,
            getStateWithDomainData(domainData)
        );

        expect(screen.queryByText('Audit Enabled')).toBeInTheDocument();
    });

    it('should render setting table for audit enabled domain with disabled role audit enabled when role audit enable is false and role has members', () => {
        let domain = 'domain';
        const domainMetadata = {
            modified: '2020-02-12T21:44:37.792Z',
            auditEnabled: true,
        };
        const domainData = buildDomainDataForState(domainMetadata, domain);
        let role = 'roleName';
        const roleDetails = {
            reviewEnabled: true,
            auditEnabled: false,
            selfServe: false,
            memberExpiryDays: 3,
            serviceExpiryDays: 3,
            tokenExpiryMins: 15,
            certExpiryMins: 15,
            roleMembers: [
                {
                    memberName: 'user.test',
                },
            ],
        };

        const { theRender } = renderWithRedux(
            <SettingTable
                category={'role'}
                domain={domain}
                collection={role}
                collectionDetails={roleDetails}
                userAuthorityAttributes={[]}
            />,
            getStateWithDomainData(domainData)
        );

        expect(
            screen.getByTestId('settingauditEnabled-switch-input')
        ).toBeDisabled();
    });

    it('should render setting table for audit enabled domain with disabled role audit enabled when role audit enable is true', () => {
        let domain = 'domain';
        const domainMetadata = {
            modified: '2020-02-12T21:44:37.792Z',
            auditEnabled: true,
        };
        const domainData = buildDomainDataForState(domainMetadata, domain);
        let role = 'roleName';
        const roleDetails = {
            reviewEnabled: true,
            auditEnabled: true,
            selfServe: false,
            memberExpiryDays: 3,
            serviceExpiryDays: 3,
            tokenExpiryMins: 15,
            certExpiryMins: 15,
        };

        const { getByTestId } = renderWithRedux(
            <SettingTable
                category={'role'}
                domain={domain}
                collection={role}
                collectionDetails={roleDetails}
                userAuthorityAttributes={[]}
            />,
            getStateWithDomainData(domainData)
        );

        expect(
            screen.getByTestId('settingauditEnabled-switch-input')
        ).toBeDisabled();
    });
});
