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
import {
    renderWithRedux,
    buildDomainDataForState,
    getStateWithDomainData,
} from '../../../tests_utils/ComponentsTestUtils';
import MockApi from '../../../mock/MockApi';
import { fireEvent, screen } from '@testing-library/react';
import DomainDetails from '../../../components/header/DomainDetails';
import * as constants from '../../../components/constants/constants';

// \* simple stable mock api \*/
const mockApi = {
    getMeta: jest.fn().mockResolvedValue([]),
};

beforeEach(() => {
    jest.resetAllMocks();
    MockApi.setMockApi(mockApi);
});

afterEach(() => {
    MockApi.cleanMockApi();
});

// helper: render DomainDetails with given org
const renderDomainDetails = ({ org, orgDomain, extraMeta = {} }) => {
    const domainMetadata = {
        modified: '2020-02-12T21:44:37.792Z',
        auditEnabled: true,
        ypmId: 'test',
        account: 'test',
        environment: 'qa',
        org,
        ...extraMeta,
    };

    const domainData = buildDomainDataForState(domainMetadata);
    const state = getStateWithDomainData(domainData);

    return renderWithRedux(<DomainDetails organization={org} />, state);
};

describe('DomainDetails', () => {
    it('should render snapshot with minimal metadata', () => {
        const domainMetadata = {
            modified: '2020-02-12T21:44:37.792Z',
            auditEnabled: false,
        };
        const domainData = buildDomainDataForState(domainMetadata);
        const state = getStateWithDomainData(domainData);

        const { getByTestId } = renderWithRedux(<DomainDetails />, state);
        expect(getByTestId('domain-details')).toMatchSnapshot();
    });

    it('should render snapshot with full metadata', () => {
        const domainMetadata = {
            modified: '2020-02-12T21:44:37.792Z',
            ypmId: 'test',
            org: 'test',
            auditEnabled: true,
            account: 'test',
            environment: 'qa',
        };
        const domainData = buildDomainDataForState(domainMetadata);
        const state = getStateWithDomainData(domainData);

        const { getByTestId } = renderWithRedux(<DomainDetails />, state);
        expect(getByTestId('domain-details')).toMatchSnapshot();
    });

    it('shows organization as link when org and orgDomain are set', () => {
        const organization = 'test-org';
        const orgDomain = 'test-domain';

        jest.spyOn(constants, 'getOrganizationDomain').mockReturnValue(
            orgDomain
        );

        renderDomainDetails({ org: organization, orgDomain });

        fireEvent.click(screen.getByTestId('expand-domain-details'));

        const orgNameNode = screen.getByTestId('organization-name');
        expect(orgNameNode).toBeInTheDocument();

        const organizationLink = screen.getByTestId('organization-link');
        expect(organizationLink).toHaveAttribute(
            'href',
            `/domain/${orgDomain}/role/${organization}/members`
        );
    });

    it('shows organization as plain text when orgDomain is empty', () => {
        const organization = 'test-org';
        const orgDomain = '';

        jest.spyOn(constants, 'getOrganizationDomain').mockReturnValue('');

        renderDomainDetails({ org: organization, orgDomain });

        fireEvent.click(screen.getByTestId('expand-domain-details'));

        const organizationLink = screen.queryByTestId('organization-link');
        expect(organizationLink).toBeNull();

        expect(screen.getByText(organization)).toBeInTheDocument();
    });

    it('shows N/A when organization is empty and orgDomain is empty', () => {
        const organization = '';
        const orgDomain = '';

        jest.spyOn(constants, 'getOrganizationDomain').mockReturnValue('');

        renderDomainDetails({ org: organization, orgDomain });

        fireEvent.click(screen.getByTestId('expand-domain-details'));

        const organizationLink = screen.queryByTestId('organization-link');
        expect(organizationLink).toBeNull();

        const organizationName = screen.getByTestId('organization-name');
        expect(organizationName).toHaveTextContent('N/A');
    });
});
