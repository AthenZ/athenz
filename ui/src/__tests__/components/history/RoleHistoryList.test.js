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
import CollectionHistoryList from '../../../components/history/CollectionHistoryList';
import { renderWithRedux } from '../../../tests_utils/ComponentsTestUtils';

describe('RoleHistoryList', () => {
    it('should render', () => {
        const startDate = '2024-01-20 07:51';
        const endDate = '2024-01-20 07:55';
        const { getByTestId } = renderWithRedux(
            <CollectionHistoryList startDate={startDate} endDate={endDate} />
        );
        const historyList = getByTestId('collection-history-list');

        expect(historyList).toMatchSnapshot();
    });
});
