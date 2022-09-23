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
import { fireEvent } from '@testing-library/react';
import Tabs from '../../../components/header/Tabs';
import { renderWithRedux } from '../../../tests_utils/ComponentsTestUtils';

describe('Tabs', () => {
    it('should render', () => {
        const api = {
            getStatus() {
                return new Promise((resolve, reject) => {
                    resolve([]);
                });
            },
        };
        const { getByTestId } = renderWithRedux(
            <Tabs selectedName='history' api={api} />
        );
        const tabs = getByTestId('tabgroup');
        const tab = tabs.querySelectorAll('.denali-tab');
        fireEvent.click(tab[0]);
        fireEvent.click(tab[1]);
        fireEvent.click(tab[2]);
        fireEvent.click(tab[3]);
        fireEvent.click(tab[4]);
        fireEvent.click(tab[5]);
        expect(tabs).toMatchSnapshot();
    });
});
