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
import DeleteModal from '../../../components/modal/DeleteModal';

describe('DeleteModal', () => {
    it('should render', () => {
        const isOpen = true;
        const cancel = function () {};
        const message = 'test';
        const name = 'name';
        const submit = function () {};
        const { getByTestId } = render(
            <DeleteModal
                isOpen={isOpen}
                cancel={cancel}
                message={message}
                name={name}
                submit={submit}
            />
        );
        const deleteModalMessage = getByTestId('delete-modal-message');
        expect(deleteModalMessage).toMatchSnapshot();
    });

    it('should render with Domain input field', () => {
        const isOpen = true;
        const cancel = function () {};
        const message = 'test';
        const name = 'name';
        const submit = function () {};
        const { getByTestId } = render(
            <DeleteModal
                isOpen={isOpen}
                cancel={cancel}
                message={message}
                name={name}
                submit={submit}
                showDomainInput={true}
            />
        );
        const deleteModalMessage = getByTestId('delete-modal-message');
        expect(deleteModalMessage).toMatchSnapshot();
    });
});
