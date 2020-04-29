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
import Home from '../../pages/home';

describe('Home', () => {
    it('should render', () => {
        let domains = [];
        domains.push({ name: 'dom1' });
        domains.push({ name: 'dom2' });
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
            <Home
                domains={domains}
                userId='test'
                headerDetails={headerDetails}
            />
        );
        const home = getByTestId('home');
        expect(home).toMatchSnapshot();
    });
});
