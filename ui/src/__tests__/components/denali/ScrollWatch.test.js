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
import ScrollWatch from '../../../components/denali/ScrollWatch';
import throttle from 'lodash/throttle';

jest.mock('lodash/throttle');

function mockThrottle(func) {
    function invokeFunc() {
        return func.apply(this, arguments);
    }

    return invokeFunc;
}
describe('ScrollWatch', () => {
    beforeEach(() =>
        jest.spyOn(React, 'createRef').mockImplementation(() => {
            return {};
        })
    );

    afterEach(() => {
        jest.resetAllMocks();
    });

    it('should handle scrolling with throttling', async () => {
        throttle.mockImplementationOnce(jest.requireActual('lodash/throttle'));

        const { getByTestId } = render(
            <ScrollWatch watchScrolledToBottom>
                {({ scrolled, scrolledToBottom, handleScroll }) => (
                    <div className='box'>
                        <div
                            className='header'
                            data-scrolled={scrolled}
                            data-scrolledtobottom={scrolledToBottom}
                            data-testid='test-header'
                        />
                        <div
                            className='scroller'
                            onScroll={handleScroll}
                            data-testid='test-scroller'
                        />
                    </div>
                )}
            </ScrollWatch>
        );

        const scrollNode = getByTestId('test-scroller');
        const header = getByTestId('test-header');

        expect(header).toHaveAttribute('data-scrolled', 'false');
        expect(header).toHaveAttribute('data-scrolledtobottom', 'false');

        /**
         * Simulate scrolling of an element by:
         * 1. Defining `clientHeight` & `scrollHeight` of the scrollable element
         * 2. Defining `scrollTop` to a non-zero value
         * 3. Fire the `scroll` event.
         */
        Object.defineProperty(scrollNode, 'clientHeight', {
            value: 600,
        });
        Object.defineProperty(scrollNode, 'scrollHeight', {
            value: 1200,
        });
        // Scroll below `scrolled` threshold
        Object.defineProperty(scrollNode, 'scrollTop', {
            value: 2, // This value won't trigger scrolled=true
            writable: true,
        });
        fireEvent.scroll(scrollNode);

        expect(header).toHaveAttribute('data-scrolled', 'false');
        expect(header).toHaveAttribute('data-scrolledtobottom', 'false');

        Object.defineProperty(scrollNode, 'scrollTop', {
            value: 100,
            writable: true,
        });
        // This should not trigger `handleScroll` since it's below throttle timeout
        fireEvent.scroll(scrollNode);

        expect(header).toHaveAttribute('data-scrolled', 'false');
        expect(header).toHaveAttribute('data-scrolledtobottom', 'false');
    });

    it('should handle scrolling (mock throttle)', async () => {
        throttle.mockImplementation(mockThrottle);

        const { getByTestId } = render(
            <ScrollWatch watchScrolledToBottom>
                {({ scrolled, scrolledToBottom, handleScroll }) => (
                    <div className='box'>
                        <div
                            className='header'
                            data-scrolled={scrolled}
                            data-scrolledtobottom={scrolledToBottom}
                            data-testid='test-header'
                        />
                        <div
                            className='scroller'
                            onScroll={handleScroll}
                            data-testid='test-scroller'
                        />
                    </div>
                )}
            </ScrollWatch>
        );

        const scrollNode = getByTestId('test-scroller');
        const header = getByTestId('test-header');

        expect(header).toHaveAttribute('data-scrolled', 'false');
        expect(header).toHaveAttribute('data-scrolledtobottom', 'false');

        /**
         * Simulate scrolling of an element by:
         * 1. Defining `clientHeight` & `scrollHeight` of the scrollable element
         * 2. Defining `scrollTop` to a non-zero value
         * 3. Fire the `scroll` event.
         */
        Object.defineProperty(scrollNode, 'clientHeight', {
            value: 600,
        });
        Object.defineProperty(scrollNode, 'scrollHeight', {
            value: 1200,
        });
        // Scroll to trigger `scrolled`
        Object.defineProperty(scrollNode, 'scrollTop', {
            value: 100,
            writable: true,
        });
        fireEvent.scroll(scrollNode);

        expect(header).toHaveAttribute('data-scrolled', 'true');
        expect(header).toHaveAttribute('data-scrolledtobottom', 'false');

        // Scroll to trigger `scrolledToBottom`
        Object.defineProperty(scrollNode, 'scrollTop', {
            value: 600,
            writable: true,
        });
        fireEvent.scroll(scrollNode);

        expect(header).toHaveAttribute('data-scrolled', 'true');
        expect(header).toHaveAttribute('data-scrolledtobottom', 'true');

        // Scroll back to the top
        // Scroll to trigger `scrolledToBottom`
        Object.defineProperty(scrollNode, 'scrollTop', {
            value: 0,
            writable: true,
        });
        fireEvent.scroll(scrollNode);

        expect(header).toHaveAttribute('data-scrolled', 'false');
        expect(header).toHaveAttribute('data-scrolledtobottom', 'false');
    });

    it('should attach ref to child element', () => {
        throttle.mockImplementation(mockThrottle);
        const createRefSpy = jest.spyOn(React, 'createRef');
        createRefSpy.mockImplementation(() => {
            return {
                current: {
                    clientHeight: 400,
                    scrollHeight: 400,
                },
            };
        });

        const { getByTestId } = render(
            <ScrollWatch watchScrolledToBottom>
                {({ scrollRef, scrolled, scrolledToBottom, handleScroll }) => (
                    <div className='box'>
                        <div
                            className='header'
                            data-scrolled={scrolled}
                            data-scrolledtobottom={scrolledToBottom}
                            data-testid='test-header'
                        />
                        <div
                            className='scroller'
                            onScroll={handleScroll}
                            ref={scrollRef}
                            style={{ height: '100px', width: '100px' }}
                            data-testid='test-scroller'
                        >
                            Some content
                        </div>
                    </div>
                )}
            </ScrollWatch>
        );
        const header = getByTestId('test-header');

        expect(createRefSpy).toHaveBeenCalledTimes(1);
        expect(header).toHaveAttribute('data-scrolled', 'false');
        // The modal's contents should fit completely within.
        expect(header).toHaveAttribute('data-scrolledtobottom', 'true');
    });

    it('should attach ref to large child element', () => {
        throttle.mockImplementation(mockThrottle);
        const createRefSpy = jest.spyOn(React, 'createRef');
        createRefSpy.mockImplementation(() => {
            return {
                current: {
                    clientHeight: 400,
                    scrollHeight: 1200,
                },
            };
        });

        const { getByTestId } = render(
            <ScrollWatch watchScrolledToBottom>
                {({ scrollRef, scrolled, scrolledToBottom, handleScroll }) => (
                    <div className='box'>
                        <div
                            className='header'
                            data-scrolled={scrolled}
                            data-scrolledtobottom={scrolledToBottom}
                            data-testid='test-header'
                        />
                        <div
                            className='scroller'
                            onScroll={handleScroll}
                            mockref={scrollRef}
                            data-testid='test-scroller'
                        />
                    </div>
                )}
            </ScrollWatch>
        );

        const header = getByTestId('test-header');

        expect(createRefSpy).toHaveBeenCalled();
        expect(header).toHaveAttribute('data-scrolled', 'false');
        // The modal should not fit inside the default test DOM.
        expect(header).toHaveAttribute('data-scrolledtobottom', 'false');
    });

    it('should ignore scrolledToBottom', () => {
        throttle.mockImplementationOnce(jest.requireActual('lodash/throttle'));

        const { getByTestId } = render(
            <ScrollWatch>
                {({ scrolled, scrolledToBottom, handleScroll }) => (
                    <div className='box'>
                        <div
                            className='header'
                            data-scrolled={scrolled}
                            data-scrolledtobottom={scrolledToBottom}
                            data-testid='test-header'
                        />
                        <div
                            className='scroller'
                            onScroll={handleScroll}
                            data-testid='test-scroller'
                        />
                    </div>
                )}
            </ScrollWatch>
        );

        const scrollNode = getByTestId('test-scroller');
        const header = getByTestId('test-header');

        expect(header).toHaveAttribute('data-scrolled', 'false');
        expect(header).not.toHaveAttribute('data-scrolledtobottom');

        /**
         * Simulate scrolling of an element by:
         * 1. Defining `clientHeight` & `scrollHeight` of the scrollable element
         * 2. Defining `scrollTop` to a non-zero value
         * 3. Fire the `scroll` event.
         */
        Object.defineProperty(scrollNode, 'clientHeight', {
            value: 600,
        });
        Object.defineProperty(scrollNode, 'scrollHeight', {
            value: 1200,
        });
        // Scroll below `scrolled` threshold
        Object.defineProperty(scrollNode, 'scrollTop', {
            value: 2, // This value won't trigger scrolled=true
            writable: true,
        });
        fireEvent.scroll(scrollNode);

        expect(header).toHaveAttribute('data-scrolled', 'false');
        expect(header).not.toHaveAttribute('data-scrolledtobottom');

        Object.defineProperty(scrollNode, 'scrollTop', {
            value: 100,
            writable: true,
        });
        // This should not trigger `handleScroll` since it's below throttle timeout
        fireEvent.scroll(scrollNode);

        expect(header).toHaveAttribute('data-scrolled', 'false');
        expect(header).not.toHaveAttribute('data-scrolledtobottom');
    });
});
