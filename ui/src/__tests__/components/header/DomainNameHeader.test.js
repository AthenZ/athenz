/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
import React from 'react';
import { render } from '@testing-library/react';
import NameHeader from '../../../components/header/NameHeader';
import DomainNameHeader from '../../../components/header/DomainNameHeader';

describe('Header', () => {
    it('should render with outline notification icon', () => {
        let domain = 'home.craman';
        let pendingCount = 0;

        const { getByTestId } = render(
            <DomainNameHeader domainName={domain} pendingCount={pendingCount} />
        );
        const header = getByTestId('domain-name-header');
        expect(header).toMatchSnapshot();
    });
    it('should render with solid notification icon', () => {
        let domain = 'home.craman';
        let pendingCount = 1;

        const { getByTestId } = render(
            <DomainNameHeader domainName={domain} pendingCount={pendingCount} />
        );
        const header = getByTestId('domain-name-header');
        expect(header).toMatchSnapshot();
    });
});
