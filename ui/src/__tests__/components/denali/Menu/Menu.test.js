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
import {
    fireEvent,
    render,
    screen,
    waitForElementToBeRemoved,
} from '@testing-library/react';
import Menu, {
    arrowMod,
    popperMod,
} from '../../../../components/denali/Menu/Menu';

// Mock PopperJS library, taken from:
// https://github.com/FezVrasta/popper.js/issues/478#issuecomment-341506071
// jest.mock('popper.js', () => {
//     const PopperJS = jest.requireActual('popper.js');
//
//     return class {
//         static placements = PopperJS.placements;
//
//         constructor() {
//             return {
//                 destroy: () => {},
//                 scheduleUpdate: () => {},
//             };
//         }
//     };
// });

describe('Menu', () => {
    it('renders the initial state (trigger only)', () => {
        const { queryByText } = render(
            <Menu trigger={<div>Trigger</div>}>
                <div className='the-menu'>A menu!</div>
            </Menu>
        );

        expect(queryByText('Trigger')).toBeInTheDocument();
        expect(queryByText('A menu!')).not.toBeInTheDocument();
    });

    it('renders a trigger as a simple string', () => {
        const { container, queryByText } = render(
            <Menu trigger='Trigger'>
                <div className='the-menu'>A menu!</div>
            </Menu>
        );

        expect(container.querySelector('span')).toBeInTheDocument();
        expect(queryByText('Trigger')).toBeInTheDocument();
    });

    it('renders menu as a simple string', async () => {
        const { getByText, queryByText } = render(
            <Menu trigger={<div className='trigger'>Trigger</div>}>
                A menu!
            </Menu>
        );

        expect(queryByText('A menu!')).not.toBeInTheDocument();

        fireEvent.mouseEnter(getByText('Trigger'));

        await screen.findByText('A menu!');
    });

    it('renders trigger as a function', async () => {
        const { getByText, queryByText } = render(
            <Menu
                trigger={({ getTriggerProps, triggerRef }) => (
                    <div
                        {...getTriggerProps({
                            className: 'trigger',
                            ref: triggerRef,
                        })}
                    >
                        Trigger
                    </div>
                )}
            >
                A menu!
            </Menu>
        );

        expect(queryByText('A menu!')).not.toBeInTheDocument();
        expect(queryByText('Trigger')).toBeInTheDocument();

        fireEvent.mouseEnter(getByText('Trigger'));

        await screen.findByText('A menu!');
    });

    // We mocked out Popper, so modifiers don't get triggered. So manually test
    // each popper.
    describe('arrowMod()', () => {
        it('works with placement "bottom"', () => {
            // Actual data is more complex, but mock only what we need
            const mockData = {
                arrowStyles: {
                    left: 40,
                    top: '',
                },
                offsets: {
                    arrowOffset: 10,
                    popper: {
                        height: 100,
                        width: 100,
                    },
                },
                placement: 'bottom',
            };
            const data = arrowMod(mockData, { arrowOffset: 15 });

            expect(data.arrowStyles.left).toBe(55);
        });

        it('works with placement "top-start"', () => {
            const mockData = {
                arrowStyles: {
                    left: 40,
                    top: '',
                },
                offsets: {
                    arrowOffset: 10,
                    popper: {
                        height: 100,
                        width: 100,
                    },
                },
                placement: 'top-start',
            };
            const data = arrowMod(mockData, { arrowOffset: 15 });

            expect(data.arrowStyles.left).toBe(25);
            expect(data.arrowStyles.top).toBe('');
        });

        it('works with placement "bottom-end"', () => {
            const mockData = {
                arrowStyles: {
                    left: 40,
                    top: '',
                },
                offsets: {
                    arrowOffset: 10,
                    popper: {
                        height: 100,
                        width: 100,
                    },
                },
                placement: 'bottom-end',
            };
            const data = arrowMod(mockData, { arrowOffset: 15 });

            expect(data.arrowStyles.left).toBe(89);
            expect(data.arrowStyles.top).toBe('');
        });

        it('works with placement "left"', () => {
            const mockData = {
                arrowStyles: {
                    left: '',
                    top: 40,
                },
                offsets: {
                    arrowOffset: 10,
                    popper: {
                        height: 100,
                        width: 100,
                    },
                },
                placement: 'left',
            };
            const data = arrowMod(mockData, { arrowOffset: 15 });

            expect(data.arrowStyles.top).toBe(55);
            expect(data.arrowStyles.left).toBe('');
        });

        it('works with placement "right-start"', () => {
            const mockData = {
                arrowStyles: {
                    left: '',
                    top: 40,
                },
                offsets: {
                    arrowOffset: 10,
                    popper: {
                        height: 100,
                        width: 100,
                    },
                },
                placement: 'right-start',
            };
            const data = arrowMod(mockData, { arrowOffset: 15 });

            expect(data.arrowStyles.top).toBe(25);
            expect(data.arrowStyles.left).toBe('');
        });

        it('works with placement "left-end"', () => {
            const mockData = {
                arrowStyles: {
                    left: '',
                    top: 40,
                },
                offsets: {
                    arrowOffset: 10,
                    popper: {
                        height: 100,
                        width: 100,
                    },
                },
                placement: 'left-end',
            };
            const data = arrowMod(mockData, { arrowOffset: 15 });

            expect(data.arrowStyles.top).toBe(89);
            expect(data.arrowStyles.left).toBe('');
        });
    });

    // We mocked out Popper, so modifiers don't get triggered. So manually test
    // each popper.
    describe('popperMod()', () => {
        it('works with placement "bottom"', () => {
            const mockData = {
                placement: 'bottom',
                styles: {
                    left: 30,
                    position: 'absolute',
                    top: 0,
                    transform: 'translate3d(356px, 21839px, 0)',
                    willChange: 'transform',
                },
            };

            const data = popperMod(mockData, { menuOffset: 10 });
            expect(data.styles.left).toBe(40);
            expect(data.styles.top).toBe(0);
        });

        it('works with placement "right"', () => {
            const mockData = {
                placement: 'right',
                styles: {
                    left: 30,
                    position: 'absolute',
                    top: 0,
                    transform: 'translate3d(356px, 21839px, 0)',
                    willChange: 'transform',
                },
            };

            const data = popperMod(mockData, { menuOffset: 10 });
            expect(data.styles.left).toBe(30);
            expect(data.styles.top).toBe(10);
        });
    });
});
