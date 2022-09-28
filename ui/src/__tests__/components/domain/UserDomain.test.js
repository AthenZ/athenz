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
import { fireEvent, render } from '@testing-library/react';
import UserDomains from '../../../components/domain/UserDomains';
import { renderWithRedux } from '../../../tests_utils/ComponentsTestUtils';
import MockApi from '../../../mock/MockApi';

describe('UserDomains', () => {
    it('should render', async () => {
        let domains = [];
        domains.push({ name: 'athens' });
        domains.push({ name: 'athens.ci' });

        const { getByTestId } = await renderWithRedux(<UserDomains />, {
            domains: { domainsList: domains },
        });
        const userDomains = getByTestId('user-domains');
        expect(userDomains).toMatchSnapshot();
    });

    it('should hide domains on click of arrow', async () => {
        let domains = [];
        domains.push({ name: 'athens' });
        domains.push({ name: 'athens.ci' });
        const { getByTestId } = await renderWithRedux(<UserDomains />, {
            domains: { domainsList: domains },
        });
        fireEvent.click(getByTestId('toggle-domain'));
        const userDomains = getByTestId('user-domains');
        expect(userDomains).toMatchSnapshot();
    });
});
