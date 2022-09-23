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
import AddModal from '../../../components/modal/AddModal';

describe('AddModal', () => {
    it('should render', () => {
        const isOpen = true;
        const cancel = function () {};
        const title = 'test';
        const sections = 'sections';
        const submit = function () {};
        const { getByTestId } = render(
            <AddModal
                isOpen={isOpen}
                cancel={cancel}
                title={title}
                sections={sections}
                submit={submit}
            />
        );
        const addModalMessage = getByTestId('add-modal-message');
        expect(addModalMessage).toMatchSnapshot();
    });

    it('should render error message', () => {
        const isOpen = true;
        const cancel = function () {};
        const title = 'test';
        const sections = 'sections';
        const submit = function () {};
        const errorMessage = 'this is error';
        const { getByText } = render(
            <AddModal
                isOpen={isOpen}
                cancel={cancel}
                title={title}
                sections={sections}
                submit={submit}
                errorMessage={errorMessage}
            />
        );
        const errorElement = getByText(errorMessage);
        expect(errorElement).toBeInTheDocument();
    });
});
