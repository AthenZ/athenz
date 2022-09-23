/*
 * CopyrightAthenz Authors
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
import ButtonGroup from '../../../components/denali/ButtonGroup';

describe('ButtonGroup', () => {
    const onClick = jest.fn();

    afterEach(() => onClick.mockClear());

    const propButtons = [
        { name: 'a', label: 'Button A' },
        { id: 'b', name: 'b', label: 'Button B' },
        { id: 'c', name: 'c', label: 'Button C' },
        { name: 'd', label: 'Button D' },
    ];

    it('should render a button group', () => {
        const { getByTestId } = render(
            <ButtonGroup
                buttons={propButtons}
                selectedName={'b'}
                onClick={onClick}
            />
        );
        const buttongroup = getByTestId('buttongroup');
        const buttonNodes = buttongroup.querySelectorAll('div');

        expect(buttongroup).toMatchSnapshot();
        expect(buttonNodes.length).toBe(4);
        expect(buttonNodes[0]).toHaveAttribute('data-active', 'false');
        expect(buttonNodes[1]).toHaveAttribute('data-active', 'true');
        expect(buttonNodes[2]).toHaveAttribute('data-active', 'false');
        expect(buttonNodes[3]).toHaveAttribute('data-active', 'false');
    });

    it('should render empty button array', () => {
        const { queryByTestId } = render(
            <ButtonGroup buttons={[]} onClick={onClick} />
        );

        expect(queryByTestId('buttongroup')).toBeNull();
    });

    it('should render a dark button group', () => {
        const { getByTestId } = render(
            <ButtonGroup buttons={propButtons} dark onClick={onClick} />
        );
        const buttongroup = getByTestId('buttongroup');

        expect(buttongroup).toMatchSnapshot();
    });

    it('should disable animations', () => {
        const { getByTestId } = render(
            <ButtonGroup buttons={propButtons} noanim onClick={onClick} />
        );
        const buttongroup = getByTestId('buttongroup');

        expect(buttongroup).toMatchSnapshot();
    });

    it('should render with additional className', () => {
        const { getByTestId } = render(
            <ButtonGroup
                buttons={propButtons}
                dark
                className='custom-class'
                onClick={onClick}
            />
        );
        const buttongroup = getByTestId('buttongroup');

        expect(buttongroup).toHaveClass('denali-button-group');
        expect(buttongroup).toHaveClass('custom-class');
    });

    it('should handle selected change with onClick', () => {
        const { getByTestId } = render(
            <ButtonGroup buttons={propButtons} onClick={onClick} />
        );
        const buttongroup = getByTestId('buttongroup');
        const buttonNodes = buttongroup.querySelectorAll('div');

        fireEvent.click(buttonNodes[0]);
        expect(onClick).not.toHaveBeenCalled();

        onClick.mockClear();
        fireEvent.click(buttonNodes[1]);
        expect(onClick).toHaveBeenLastCalledWith({
            id: 'b',
            label: 'Button B',
            name: 'b',
        });

        onClick.mockClear();
        fireEvent.click(buttonNodes[2]);
        expect(onClick).toHaveBeenLastCalledWith({
            id: 'c',
            label: 'Button C',
            name: 'c',
        });

        onClick.mockClear();
        fireEvent.click(buttonNodes[3]);
        expect(onClick).toHaveBeenLastCalledWith({
            label: 'Button D',
            name: 'd',
        });
    });
});
