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
import Search from '../../pages/search';

describe('Search', () => {
    it('should render', () => {
        let domains = [];
        domains.push({ name: 'athens' });
        domains.push({ name: 'athens.ci' });

        let result = {
            name: 'test1',
            adminDomain: true,
        };
        let domainResults = [];
        domainResults.push(result);
        let headerDetails = {
            headerLinks: [
                {
                    title: 'Website',
                    url: 'http://www.athenz.io',
                    target: '_blank',
                },
            ],
        };

        const { getByTestId } = render(
            <Search
                domains={domains}
                domain='test'
                type='domain'
                domainResults={domainResults}
                userId={'pgote'}
                headerDetails={headerDetails}
            />
        );
        const search = getByTestId('search');
        expect(search).toMatchSnapshot();
    });
});
