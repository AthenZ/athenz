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
import { fireEvent, render } from '@testing-library/react';
import Modal from '../../../components/denali/Modal';

describe('Modal', () => {
    const onClose = jest.fn();

    afterEach(() => onClose.mockClear());

    it('should render nothing in closed state', () => {
        const { baseElement } = render(
            <Modal title='A modal' isOpen={false} onClose={onClose} />
        );

        expect(baseElement.querySelector('.denali-modal')).toBeNull();
    });

    it('should render open state', () => {
        const { baseElement, queryByTestId } = render(
            <Modal title='A modal' isOpen={true} onClose={onClose}>
                Modal content
            </Modal>
        );

        expect(baseElement).toMatchSnapshot();
        expect(baseElement.querySelector('.denali-modal')).not.toBeNull();
    });

    it('should render with title as an element', () => {
        const title = (
            <div data-testid='custom-modal-title'>
                <b>Bold</b> not bold
            </div>
        );
        const { queryByTestId } = render(
            <Modal title={title} isOpen={true} onClose={onClose}>
                Modal content
            </Modal>
        );
    });

    it('should render with an additional class name', () => {
        const { baseElement } = render(
            <Modal
                className='custom-class'
                title='A modal'
                isOpen={true}
                onClose={onClose}
            >
                Modal content
            </Modal>
        );
        const portal = baseElement.querySelector('.denali-modal');

        expect(portal).toHaveClass('denali-modal');
        expect(portal).toHaveClass('custom-class');
    });

    it('should handle onClose event', () => {
        const { baseElement } = render(
            <Modal title='A modal' isOpen={true} onClose={onClose}>
                Modal content
            </Modal>
        );

        fireEvent.click(baseElement.querySelector('.close-button'));

        expect(onClose).toHaveBeenCalled();
    });

    it('should not close on overlay click', () => {
        const { baseElement } = render(
            <Modal
                title='A non-clickable overlay modal'
                isOpen={true}
                onClose={onClose}
            >
                Modal content
            </Modal>
        );

        fireEvent.click(baseElement.querySelector('.react-modal-overlay'));

        expect(onClose).not.toHaveBeenCalled();
        expect(baseElement.querySelector('.denali-modal')).not.toBeNull();
    });

    it('should close on overlay click', () => {
        const { baseElement } = render(
            <Modal
                title='A clickable overlay modal'
                isOpen={true}
                shouldCloseOnOverlayClick={true}
                onClose={onClose}
            >
                Modal content
            </Modal>
        );

        fireEvent.click(baseElement.querySelector('.react-modal-overlay'));

        expect(onClose).toHaveBeenCalled();
    });

    it('should handle scrolling', () => {
        const { getByTestId } = render(
            <Modal title='A modal' isOpen={true} onClose={onClose}>
                Modal content
            </Modal>
        );

        const modalContent = getByTestId('modal-content');
        const header = getByTestId('modal-header');

        expect(header).not.toHaveClass('scrolled');

        /**
         * Simulate scrolling of an element by:
         * 1. Defining `clientHeight` & `scrollHeight` of the scrollable element
         * 2. Defining `scrollTop` to a non-zero value
         * 3. Fire the `scroll` event.
         */
        Object.defineProperty(modalContent, 'clientHeight', {
            value: 600,
        });
        Object.defineProperty(modalContent, 'scrollHeight', {
            value: 1200,
        });
        Object.defineProperty(modalContent, 'scrollTop', {
            value: 100,
            writable: true,
        });
        fireEvent.scroll(modalContent);

        expect(header).toHaveClass('scrolled');
    });
});
