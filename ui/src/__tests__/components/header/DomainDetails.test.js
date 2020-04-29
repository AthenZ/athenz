/*
 * Copyright 2020 Verizon Media
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
import { render } from '@testing-library/react';
import DomainDetails from '../../../components/header/DomainDetails';

describe('DomainDetails', () => {
    it('should render', () => {
        const domainMetadata = {
            modified: '2020-02-12T21:44:37.792Z',
        };

        const { getByTestId } = render(
            <DomainDetails domainDetails={domainMetadata} />
        );
        const domainDetails = getByTestId('domain-details');
        expect(domainDetails).toMatchSnapshot();
    });
    it('should render with mock data', () => {
        const domainMetadata = {
            modified: '2020-02-12T21:44:37.792Z',
            ypmId: 'test',
            org: 'test',
            auditEnabled: true,
            account: 'test',
        };

        const { getByTestId } = render(
            <DomainDetails domainDetails={domainMetadata} />
        );
        const domainDetails = getByTestId('domain-details');
        expect(domainDetails).toMatchSnapshot();
    });
});
