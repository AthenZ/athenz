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
import AddTagForm from '../../../components/tag/AddTagForm';
import API from '../../../api';
import { fireEvent, render, waitFor, screen } from '@testing-library/react';

describe('AddTagForm', () => {
    const onUpdate = jest.fn();

    let newTagProps = {
        api: API(),
        onUpdate: onUpdate,
    };

    it('should render on new tag', () => {
        const { getByTestId } = render(<AddTagForm {...newTagProps} />);
        const addTagForm = getByTestId('add-tag-form');
        expect(addTagForm).toMatchSnapshot();
        expect(
            screen.getByPlaceholderText('Enter New Tag Name')
        ).toBeInTheDocument();
        expect(
            screen.getByPlaceholderText('Enter New Tag Value')
        ).toBeInTheDocument();
    });

    it('should render on edit tag', () => {
        const { getByTestId } = render(
            <AddTagForm
                api={API()}
                onUpdate={onUpdate}
                editedTagKey={'tagName'}
                editedTagValues={['val1', 'val2']}
            />
        );
        const addTagForm = getByTestId('add-tag-form');
        expect(addTagForm).toMatchSnapshot();
        expect(
            screen.getByPlaceholderText('Enter New Tag Name')
        ).toBeInTheDocument();
        expect(
            screen.getByPlaceholderText('Enter New Tag Value')
        ).toBeInTheDocument();

        // tag name and values are presented
        expect(screen.getByDisplayValue('tagName')).toBeInTheDocument();
        expect(screen.getByText('val1')).toBeInTheDocument();
        expect(screen.getByText('val2')).toBeInTheDocument();
    });

    it('should add delete key and values', () => {
        render(<AddTagForm {...newTagProps} />);

        // add invalid tag name
        fireEvent.change(screen.getByPlaceholderText('Enter New Tag Name'), {
            target: { value: '' },
        });

        // add tag name
        fireEvent.change(screen.getByPlaceholderText('Enter New Tag Name'), {
            target: { value: 'tag-name' },
        });
        expect(screen.getByDisplayValue('tag-name')).toBeInTheDocument();

        // add tag values
        fireEvent.change(screen.getByPlaceholderText('Enter New Tag Value'), {
            target: { value: 'first,second' },
        });
        // click add button
        fireEvent.click(screen.getAllByRole('button')[0]);
        expect(screen.getByText('first')).toBeInTheDocument();
        expect(screen.getByText('second')).toBeInTheDocument();

        // delete first tag
        fireEvent.click(screen.getAllByText('x')[0]);
        expect(screen.queryByText('first')).not.toBeInTheDocument();
        expect(screen.getByText('second')).toBeInTheDocument();
    });
});
