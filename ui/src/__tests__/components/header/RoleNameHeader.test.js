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
import { render } from '@testing-library/react';
import NameHeader from '../../../components/header/NameHeader';

describe('Header', () => {
    it('should render', () => {
        let domain = 'home.mujibur';
        let role = 'admin';
        let roleDetails = {
            trust: null,
            auditEnabled: false,
        };
        const { getByTestId } = render(
            <NameHeader
                showSearch={false}
                domain={domain}
                collection={role}
                collectionDetails={roleDetails}
            />
        );
        const header = getByTestId('collection-name-header');
        expect(header).toMatchSnapshot();
    });
    it('should render audit enabled role', () => {
        let domain = 'home.mujibur';
        let role = 'audit.role';
        let roleDetails = {
            trust: null,
            auditEnabled: true,
        };
        const { getByTestId } = render(
            <NameHeader
                showSearch={false}
                domain={domain}
                collection={role}
                collectionDetails={roleDetails}
            />
        );
        const header = getByTestId('collection-name-header');
        expect(header).toMatchSnapshot();
    });
    it('should render delegated role', () => {
        let domain = 'home.mujibur';
        let role = 'delegated.role';
        let roleDetails = {
            trust: 'home.hga',
            auditEnabled: false,
        };
        const { getByTestId } = render(
            <NameHeader
                showSearch={false}
                domain={domain}
                collection={role}
                collectionDetails={roleDetails}
            />
        );
        const header = getByTestId('collection-name-header');
        expect(header).toMatchSnapshot();
    });
});
