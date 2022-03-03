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
import API from '../../../api';
import { fireEvent, render, screen, waitFor } from '@testing-library/react';
import TagRow from '../../../components/tag/TagRow';

describe('TagRow', () => {
    it('should render tag row', () => {
        const { getByTestId } = render(
            <TagRow
                api={API()}
                tagKey={'tagName'}
                tagValues={{ list: ['val1', 'val2'] }}
            />
        );
        const addTagForm = getByTestId('tag-row');
        expect(addTagForm).toMatchSnapshot();
        // delete tag icon
        expect(screen.getByTitle('trash')).toBeInTheDocument();
        // edit tag icon
        expect(screen.getByTitle('edit')).toBeInTheDocument();

        // tag key and values
        expect(screen.getByText('tagName')).toBeInTheDocument();
        expect(screen.getByText('val1')).toBeInTheDocument();
        expect(screen.getByText('val2')).toBeInTheDocument();
    });

    it('should click edit and delete', async () => {
        let rowProps = {
            api: API(),
            tagKey: 'tagName',
            tagValues: { list: ['val1', 'val2'] },
            onClickDeleteTagValue: jest.fn(),
            onClickEditTag: jest.fn(),
        };
        const { getByTestId } = render(<TagRow {...rowProps} />);
        const addTagForm = getByTestId('tag-row');
        expect(addTagForm).toMatchSnapshot();
        // delete tag icon
        expect(screen.getByTitle('trash')).toBeInTheDocument();
        // edit tag icon
        expect(screen.getByTitle('edit')).toBeInTheDocument();

        // click Edit button
        fireEvent.click(screen.getByTitle('edit'));
        await waitFor(() => {
            expect(rowProps.onClickEditTag.mock.calls.length).toBe(1);
        });

        // click delete tag value
        fireEvent.click(screen.getAllByText('x')[0]);
        await waitFor(() => {
            expect(rowProps.onClickDeleteTagValue.mock.calls.length).toBe(1);
        });
    });
});
