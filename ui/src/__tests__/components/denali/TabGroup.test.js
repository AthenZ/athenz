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
import TabGroup from '../../../components/denali/TabGroup';

describe('TabGroup', () => {
    const onClick = jest.fn();

    afterEach(() => onClick.mockClear());

    const propTabs = [
        {
            label: 'Tab A',
            name: 'a',
        },
        {
            id: 'b',
            label: <div>Extra long Tab B</div>,
            name: 'b',
        },
        {
            id: 'c',
            label: function label() {
                return <div>Tab C</div>;
            },
            name: 'c',
            disabled: true,
        },
    ];

    it('should render primary tabs', () => {
        const { getByTestId } = render(
            <TabGroup name='tabs-1' tabs={propTabs} onClick={onClick} />
        );
        const tabgroup = getByTestId('tabgroup');
        const tabs = tabgroup.querySelectorAll('.denali-tab');

        expect(tabgroup).toMatchSnapshot();
        expect(tabs.length).toBe(3);
        expect(tabs[0]).toHaveAttribute('data-active', 'true');
        expect(tabs[1]).toHaveAttribute('data-active', 'false');
        expect(tabs[2]).toHaveAttribute('data-active', 'false');
        expect(tabgroup).toHaveStyle(`grid-template-columns: repeat(3, 1fr)`);
    });

    it('should not render with empty tabs array', () => {
        const { queryByTestId } = render(
            <TabGroup name='tabs-2' tabs={[]} onClick={onClick} />
        );

        expect(queryByTestId('tabgroup')).toBeNull();
    });

    it('should render with selectedName', () => {
        const { getByTestId } = render(
            <TabGroup
                name='tabs-3'
                tabs={propTabs}
                selectedName='b'
                onClick={onClick}
            />
        );
        const tabgroup = getByTestId('tabgroup');
        const tabs = tabgroup.querySelectorAll('.denali-tab');

        expect(tabs[0]).toHaveAttribute('data-active', 'false');
        expect(tabs[1]).toHaveAttribute('data-active', 'true');
        expect(tabs[2]).toHaveAttribute('data-active', 'false');
    });

    it('should render secondary tabs', () => {
        const { getByTestId } = render(
            <TabGroup
                name='tabs-4'
                tabs={propTabs}
                secondary
                onClick={onClick}
            />
        );
        const tabgroup = getByTestId('tabgroup');

        expect(tabgroup).toMatchSnapshot();
    });

    it('should render vertical tabs', () => {
        const { getByTestId } = render(
            <TabGroup
                name='tabs-5'
                tabs={propTabs}
                direction='vertical'
                onClick={onClick}
            />
        );
        const tabgroup = getByTestId('tabgroup');

        expect(tabgroup).toMatchSnapshot();
    });

    it('should render dynamic width tabs', () => {
        const { getByTestId } = render(
            <TabGroup
                equalWidth={false}
                name='tabs-6'
                tabs={propTabs}
                onClick={onClick}
            />
        );
        const tabgroup = getByTestId('tabgroup');

        expect(tabgroup).toHaveStyle(`grid-template-columns: repeat(3, auto)`);
    });

    it('should render with an additional class name', () => {
        const { getByTestId } = render(
            <TabGroup
                className='custom-class'
                tabs={propTabs}
                name='tabs-7'
                onClick={onClick}
            />
        );
        const tabgroup = getByTestId('tabgroup');

        expect(tabgroup).toHaveClass('denali-tab-group');
        expect(tabgroup).toHaveClass('custom-class');
    });

    it('should handle updating of props', () => {
        const { getByTestId, rerender } = render(
            <TabGroup name='tabs-8' tabs={propTabs} onClick={onClick} />
        );
        const tabgroup = getByTestId('tabgroup');
        const tabs = tabgroup.querySelectorAll('.denali-tab');

        expect(tabs[0]).toHaveAttribute('data-active', 'true');
        expect(tabs[1]).toHaveAttribute('data-active', 'false');
        expect(tabs[2]).toHaveAttribute('data-active', 'false');

        rerender(
            <TabGroup
                name='tabs-9'
                tabs={propTabs}
                selectedName='c'
                onClick={onClick}
            />
        );

        expect(tabs[0]).toHaveAttribute('data-active', 'false');
        expect(tabs[1]).toHaveAttribute('data-active', 'false');
        expect(tabs[2]).toHaveAttribute('data-active', 'true');
    });

    it('should disable animations', () => {
        const { getByTestId } = render(
            <TabGroup name='tabs-10' tabs={propTabs} noanim onClick={onClick} />
        );
        const tabgroup = getByTestId('tabgroup');

        expect(tabgroup).toMatchSnapshot();
    });

    it('should handle onClick event', () => {
        const { getByTestId } = render(
            <TabGroup
                name='tabs-11'
                tabs={propTabs}
                selectedName='b'
                onClick={onClick}
            />
        );
        const tabgroup = getByTestId('tabgroup');
        const tabs = tabgroup.querySelectorAll('.denali-tab');

        fireEvent.click(tabs[0]);

        expect(onClick).toHaveBeenLastCalledWith({ label: 'Tab A', name: 'a' });

        onClick.mockClear();
        fireEvent.click(tabs[1]);

        expect(onClick).not.toHaveBeenCalled();

        fireEvent.click(tabs[2]);

        expect(onClick).not.toHaveBeenCalled();
    });
});
