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
/* eslint-disable no-console */
import React from 'react';
import { fireEvent, queryByText, render } from '@testing-library/react';
import Alert from '../../../components/denali/Alert';
import { act } from 'react-test-renderer';

jest.useFakeTimers();

describe('Alert', () => {
    const onClose = jest.fn();

    beforeEach(() => {
        jest.clearAllMocks();
        jest.clearAllTimers();
        jest.spyOn(global, 'setTimeout');
        jest.spyOn(global, 'clearTimeout');
    });

    afterEach(() => {
        global.setTimeout.mockRestore();
        global.clearTimeout.mockRestore();
    });

    it('should render nothing in closed state', () => {
        const { baseElement } = render(
            <Alert
                title='An Alert'
                description='Alert Description'
                isOpen={false}
                onClose={onClose}
            />
        );

        expect(queryByText(baseElement, 'An Alert')).toBeNull();
        expect(setTimeout).not.toHaveBeenCalled();
    });

    it('should render open state', (done) => {
        const { baseElement } = render(
            <Alert
                title='An Alert'
                description='Descriptive Alert'
                isOpen={true}
                onClose={onClose}
            />
        );

        expect(baseElement).toMatchSnapshot();
        expect(queryByText(baseElement, 'An Alert')).toBeInTheDocument();
        expect(queryByText(baseElement, 'Descriptive Alert')).not.toBeNull();
        expect(baseElement.querySelector('.animated')).toBeInTheDocument();

        // Ensure alert does not close on timer

        act(() => jest.runAllTimers());

        try {
            expect(queryByText(baseElement, 'An Alert')).toBeInTheDocument();
            done();
        } catch (error) {
            done.fail(error);
        }
        // });
    });

    it('should render all alert types', () => {
        const { baseElement, rerender } = render(
            <Alert
                title='An Alert'
                isOpen={true}
                type='danger'
                onClose={onClose}
            />
        );

        expect(baseElement).toMatchSnapshot();
        expect(
            baseElement.querySelector('.denali-alert-danger')
        ).not.toBeNull();

        rerender(
            <Alert
                title='An Alert'
                isOpen={true}
                type='info'
                onClose={onClose}
            />
        );

        expect(baseElement).toMatchSnapshot();
        expect(baseElement.querySelector('.denali-alert-info')).not.toBeNull();

        rerender(
            <Alert
                title='An Alert'
                isOpen={true}
                type='success'
                onClose={onClose}
            />
        );

        expect(baseElement).toMatchSnapshot();
        expect(
            baseElement.querySelector('.denali-alert-success')
        ).not.toBeNull();

        rerender(
            <Alert
                title='An Alert'
                isOpen={true}
                type='warning'
                onClose={onClose}
            />
        );

        expect(baseElement).toMatchSnapshot();
        expect(
            baseElement.querySelector('.denali-alert-warning')
        ).not.toBeNull();
    });

    it('should disable animations', () => {
        const { baseElement } = render(
            <Alert
                title='An Alert'
                description='Descriptive Alert'
                isOpen={true}
                noanim
                onClose={onClose}
            />
        );

        expect(baseElement).toMatchSnapshot();
        expect(baseElement.querySelector('.animated')).not.toBeInTheDocument();
    });

    it('should render with an additional class name', () => {
        const { baseElement } = render(
            <Alert
                className='custom-class'
                title='An Alert'
                isOpen={true}
                onClose={onClose}
            />
        );
        const portal = baseElement.querySelector('.denali-alert');

        expect(portal).toHaveClass('denali-alert');
        expect(portal).toHaveClass('custom-class');
    });

    it('should handle onClose event', () => {
        const { baseElement } = render(
            <Alert title='An Alert' isOpen={true} onClose={onClose} />
        );

        fireEvent.click(baseElement.querySelector('.close-button'));

        expect(onClose).toHaveBeenCalled();
    });

    it('should handle timed close', (done) => {
        expect(setTimeout).not.toHaveBeenCalled();

        const { baseElement } = render(
            <Alert
                title='An Alert'
                isOpen={true}
                duration={5000}
                onClose={onClose}
            />
        );

        expect(queryByText(baseElement, 'An Alert')).not.toBeNull();

        expect(setTimeout).toHaveBeenCalledTimes(1);
        expect(onClose).not.toHaveBeenCalled();

        act(() => jest.runAllTimers());

        expect(onClose).toHaveBeenCalledTimes(1);
        done();
    });

    it('should set timer after Alert initially closed', (done) => {
        expect(setTimeout).not.toHaveBeenCalled();

        const { baseElement, rerender } = render(
            <Alert
                title='An Alert'
                isOpen={false}
                duration={5000}
                onClose={onClose}
            />
        );

        expect(queryByText(baseElement, 'An Alert')).toBeNull();

        expect(setTimeout).not.toHaveBeenCalled();

        rerender(
            <Alert
                title='An Alert'
                isOpen={true}
                duration={5000}
                onClose={onClose}
            />
        );

        expect(setTimeout).toHaveBeenCalledTimes(1);

        act(() => jest.runAllTimers());

        try {
            expect(onClose).toHaveBeenCalledTimes(1);
            done();
        } catch (error) {
            done.fail(error);
        }
    });

    it('should handle closing Alert before timer expires', (done) => {
        expect(setTimeout).not.toHaveBeenCalled();

        const { baseElement, rerender } = render(
            <Alert
                title='An Alert'
                isOpen={true}
                duration={5000}
                onClose={onClose}
            />
        );

        expect(queryByText(baseElement, 'An Alert')).not.toBeNull();
        expect(setTimeout).toHaveBeenCalled();

        rerender(
            <Alert
                title='An Alert'
                isOpen={false}
                duration={5000}
                onClose={onClose}
            />
        );

        expect(clearTimeout).toHaveBeenCalled();

        act(() => jest.runAllTimers());

        try {
            expect(onClose).not.toHaveBeenCalled();
            done();
        } catch (error) {
            done.fail(error);
        }
        // });
    });

    it('should handle unmounting with timer', (done) => {
        expect(setTimeout).not.toHaveBeenCalled();
        expect(clearTimeout).not.toHaveBeenCalled();

        const { baseElement, unmount } = render(
            <Alert
                title='An Alert'
                isOpen={true}
                duration={5000}
                onClose={onClose}
            />
        );

        expect(baseElement.querySelector('.denali-alert')).not.toBeNull();

        expect(setTimeout).toHaveBeenCalledTimes(1);
        expect(clearTimeout).not.toHaveBeenCalled();
        expect(onClose).not.toHaveBeenCalled();

        unmount();

        act(() => jest.runAllTimers());

        try {
            // NOTE: For some reason, clearTimeout() actually gets called twice, but I
            // haven't been able to figure out why. Even if clearTimeout() is commented
            // out, it's still called. So just check if it was called, not how many
            // times it was called
            expect(clearTimeout).toHaveBeenCalled();
            expect(onClose).not.toHaveBeenCalled();
            done();
        } catch (error) {
            done.fail(error);
        }
    });
});
