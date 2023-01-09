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
import AddTag from '../../../components/tag/AddTag';
import MockApi from '../../../mock/MockApi';

describe('AddTag', () => {
    const onCancel = jest.fn();
    beforeEach(() => {
        MockApi.setMockApi({
            getPendingDomainMembersList: jest.fn().mockReturnValue([]),
        });
    });
    afterEach(() => MockApi.cleanMockApi());
    it('should render on new tag', () => {
        const { getByTestId } = render(
            <AddTag onCancel={onCancel} showAddTag={true} api={API()} />
        );
        const addTagForm = getByTestId('add-modal-message');
        expect(addTagForm).toMatchSnapshot();
        expect(
            screen.getByPlaceholderText('Enter New Tag Name')
        ).toBeInTheDocument();
        expect(
            screen.getByPlaceholderText('Enter New Tag Value')
        ).toBeInTheDocument();
    });

    it('should render on edit tag with err message', () => {
        render(
            <AddTag
                onCancel={onCancel}
                showAddTag={true}
                editMode={true}
                resource={'tag-resource'}
                api={API()}
                editedTagKey={'edit-tag-name'}
                editedTagValues={['tag1', 'tag2']}
                errorMessage={'some-err-msg'}
            />
        );
        expect(
            screen.getByPlaceholderText('Enter New Tag Name')
        ).toBeInTheDocument();
        expect(
            screen.getByPlaceholderText('Enter New Tag Value')
        ).toBeInTheDocument();

        // tag name and values are presented
        expect(screen.getByDisplayValue('edit-tag-name')).toBeInTheDocument();
        expect(screen.getByText('tag1')).toBeInTheDocument();
        expect(screen.getByText('tag2')).toBeInTheDocument();
        expect(screen.getByText('some-err-msg')).toBeInTheDocument();
        expect(screen.getByText('Edit edit-tag-name Tag')).toBeInTheDocument();
    });

    it('should include tag name', async () => {
        render(
            <AddTag
                onCancel={onCancel}
                showAddTag={true}
                api={API()}
                resource={'tag-resource'}
                validateTagExist={jest.fn().mockReturnValue(true)}
            />
        );
        await waitFor(() => screen.getByText('Add Tag to tag-resource'));
        expect(
            screen.getByPlaceholderText('Enter New Tag Name')
        ).toBeInTheDocument();
        expect(
            screen.getByPlaceholderText('Enter New Tag Value')
        ).toBeInTheDocument();

        // click Submit button
        fireEvent.click(screen.getByText('Submit'));
        expect(screen.getByText('Tag name is required.')).toBeInTheDocument();

        // add tag name
        fireEvent.change(screen.getByPlaceholderText('Enter New Tag Name'), {
            target: { value: 'tag-name' },
        });
        // click Submit button
        fireEvent.click(screen.getByText('Submit'));
        expect(screen.getByText('Tag already exist.')).toBeInTheDocument();
    });

    it('should include tag value', async () => {
        let addTagProps = {
            onCancel: onCancel,
            showAddTag: true,
            api: API(),
            resource: 'tag-resource',
            validateTagExist: jest.fn().mockReturnValue(false),
            addNewTag: jest.fn(),
        };
        render(<AddTag {...addTagProps} />);
        await waitFor(() => screen.getByText('Add Tag to tag-resource'));
        expect(
            screen.getByPlaceholderText('Enter New Tag Name')
        ).toBeInTheDocument();
        expect(
            screen.getByPlaceholderText('Enter New Tag Value')
        ).toBeInTheDocument();

        // add tag name
        fireEvent.change(screen.getByPlaceholderText('Enter New Tag Name'), {
            target: { value: 'tag-name' },
        });
        // click Submit button
        fireEvent.click(screen.getByText('Submit'));
        expect(screen.getByText('Tag value is required.')).toBeInTheDocument();

        // click add before value exist - should do nothing
        fireEvent.click(screen.getByText('Add'));

        // add tag values
        fireEvent.change(screen.getByPlaceholderText('Enter New Tag Value'), {
            target: { value: 'first,second' },
        });
        // click add button
        fireEvent.click(screen.getByText('Add'));
        expect(screen.getByText('first')).toBeInTheDocument();
        expect(screen.getByText('second')).toBeInTheDocument();

        // add third tag without add button
        fireEvent.change(screen.getByPlaceholderText('Enter New Tag Value'), {
            target: { value: 'third' },
        });

        // click Submit button
        fireEvent.click(screen.getByText('Submit'));

        // verify addNewTag
        await waitFor(() => {
            expect(addTagProps.addNewTag.mock.calls.length).toBe(1);
        });
    });
});
