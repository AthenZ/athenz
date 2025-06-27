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
import { render, screen, fireEvent } from '@testing-library/react';
import PageSizeSelector from '../../../components/member/PageSizeSelector';

describe('PageSizeSelector', () => {
    const defaultProps = {
        value: 30,
        options: [30, 50, 100],
        onChange: jest.fn(),
        label: 'Show',
    };

    beforeEach(() => {
        jest.clearAllMocks();
    });

    describe('rendering', () => {
        it('should render page size selector', () => {
            render(<PageSizeSelector {...defaultProps} />);

            expect(screen.getByText('Show')).toBeInTheDocument();
            expect(screen.getByDisplayValue('30')).toBeInTheDocument();
            expect(screen.queryByText('per page')).not.toBeInTheDocument();
        });

        it('should render with custom label', () => {
            render(<PageSizeSelector {...defaultProps} label='Items' />);

            expect(screen.getByText('Items')).toBeInTheDocument();
        });

        it('should render without label', () => {
            render(<PageSizeSelector {...defaultProps} label='' />);

            expect(screen.queryByText('Show')).not.toBeInTheDocument();
            expect(screen.getByDisplayValue('30')).toBeInTheDocument();
            expect(screen.queryByText('per page')).not.toBeInTheDocument();
        });

        it('should render all available options', () => {
            render(<PageSizeSelector {...defaultProps} />);

            const select = screen.getByDisplayValue('30');
            fireEvent.click(select);

            expect(
                screen.getByRole('option', { name: '30' })
            ).toBeInTheDocument();
            expect(
                screen.getByRole('option', { name: '50' })
            ).toBeInTheDocument();
            expect(
                screen.getByRole('option', { name: '100' })
            ).toBeInTheDocument();
        });

        it('should show selected value correctly', () => {
            render(<PageSizeSelector {...defaultProps} value={50} />);

            expect(screen.getByDisplayValue('50')).toBeInTheDocument();
        });

        it('should render with custom options', () => {
            const customOptions = [10, 25, 50, 100];
            render(
                <PageSizeSelector
                    {...defaultProps}
                    options={customOptions}
                    value={25}
                />
            );

            const select = screen.getByDisplayValue('25');
            fireEvent.click(select);

            expect(
                screen.getByRole('option', { name: '10' })
            ).toBeInTheDocument();
            expect(
                screen.getByRole('option', { name: '25' })
            ).toBeInTheDocument();
            expect(
                screen.getByRole('option', { name: '50' })
            ).toBeInTheDocument();
            expect(
                screen.getByRole('option', { name: '100' })
            ).toBeInTheDocument();
        });
    });

    describe('interactions', () => {
        it('should call onChange when selection changes', () => {
            render(<PageSizeSelector {...defaultProps} />);

            const select = screen.getByDisplayValue('30');
            fireEvent.change(select, { target: { value: '50' } });

            expect(defaultProps.onChange).toHaveBeenCalledWith(50);
        });

        it('should call onChange with correct value for each option', () => {
            render(<PageSizeSelector {...defaultProps} />);

            const select = screen.getByDisplayValue('30');

            fireEvent.change(select, { target: { value: '100' } });
            expect(defaultProps.onChange).toHaveBeenCalledWith(100);

            fireEvent.change(select, { target: { value: '50' } });
            expect(defaultProps.onChange).toHaveBeenCalledWith(50);
        });

        it('should handle string values correctly', () => {
            render(<PageSizeSelector {...defaultProps} />);

            const select = screen.getByDisplayValue('30');
            fireEvent.change(select, { target: { value: '50' } });

            expect(defaultProps.onChange).toHaveBeenCalledWith(50);
            expect(typeof defaultProps.onChange.mock.calls[0][0]).toBe(
                'number'
            );
        });
    });

    describe('accessibility', () => {
        it('should have proper aria labels', () => {
            render(<PageSizeSelector {...defaultProps} />);

            const select = screen.getByRole('combobox');
            expect(select).toHaveAttribute('aria-label', 'Select page size');
        });

        it('should be keyboard navigable', () => {
            render(<PageSizeSelector {...defaultProps} />);

            const select = screen.getByDisplayValue('30');
            select.focus();
            expect(select).toHaveFocus();

            fireEvent.keyDown(select, { key: 'ArrowDown' });
            fireEvent.keyDown(select, { key: 'Enter' });

            // Should still be focusable after interaction
            expect(select).toBeInTheDocument();
        });

        it('should have proper label association', () => {
            render(<PageSizeSelector {...defaultProps} />);

            const select = screen.getByDisplayValue('30');
            expect(select).toHaveAttribute('id');
        });
    });

    describe('edge cases', () => {
        it('should handle empty options array', () => {
            render(<PageSizeSelector {...defaultProps} options={[]} />);

            const select = screen.getByDisplayValue('30');
            expect(select).toBeInTheDocument();
        });

        it('should handle single option', () => {
            render(<PageSizeSelector {...defaultProps} options={[30]} />);

            const select = screen.getByDisplayValue('30');
            fireEvent.click(select);

            expect(
                screen.getByRole('option', { name: '30' })
            ).toBeInTheDocument();
        });

        it('should handle value not in options', () => {
            render(
                <PageSizeSelector
                    {...defaultProps}
                    value={75}
                    options={[30, 50, 100]}
                />
            );

            expect(screen.getByDisplayValue('75')).toBeInTheDocument();
        });

        it('should handle zero value', () => {
            render(<PageSizeSelector {...defaultProps} value={0} />);

            expect(screen.getByDisplayValue('0')).toBeInTheDocument();
        });

        it('should handle large numbers', () => {
            const largeOptions = [1000, 5000, 10000];
            render(
                <PageSizeSelector
                    {...defaultProps}
                    options={largeOptions}
                    value={5000}
                />
            );

            expect(screen.getByDisplayValue('5000')).toBeInTheDocument();
        });
    });

    describe('styling and layout', () => {
        it('should apply custom CSS classes', () => {
            const { container } = render(
                <PageSizeSelector
                    {...defaultProps}
                    className='custom-selector'
                />
            );

            expect(container.firstChild).toHaveClass('custom-selector');
        });

        it('should render in compact mode', () => {
            render(<PageSizeSelector {...defaultProps} compact={true} />);

            // In compact mode, label might be hidden or styled differently
            const container = screen.getByDisplayValue('30').closest('div');
            expect(container).toBeInTheDocument();
        });

        it('should handle disabled state', () => {
            render(<PageSizeSelector {...defaultProps} disabled={true} />);

            const select = screen.getByDisplayValue('30');
            expect(select).toBeDisabled();
        });
    });

    describe('error handling', () => {
        it('should handle missing onChange gracefully', () => {
            const { onChange, ...propsWithoutOnChange } = defaultProps;
            render(<PageSizeSelector {...propsWithoutOnChange} />);

            const select = screen.getByDisplayValue('30');
            expect(() => {
                fireEvent.change(select, { target: { value: '50' } });
            }).not.toThrow();
        });

        it('should handle invalid value types', () => {
            render(<PageSizeSelector {...defaultProps} />);

            const select = screen.getByDisplayValue('30');
            fireEvent.change(select, { target: { value: 'invalid' } });

            // Should convert to number or handle gracefully
            expect(defaultProps.onChange).toHaveBeenCalledWith(NaN);
        });
    });

    describe('integration scenarios', () => {
        it('should work with form submission', () => {
            const onSubmit = jest.fn();

            render(
                <form onSubmit={onSubmit}>
                    <PageSizeSelector {...defaultProps} />
                    <button type='submit'>Submit</button>
                </form>
            );

            const select = screen.getByDisplayValue('30');
            fireEvent.change(select, { target: { value: '100' } });

            expect(defaultProps.onChange).toHaveBeenCalledWith(100);
        });

        it('should maintain state across re-renders', () => {
            const { rerender } = render(
                <PageSizeSelector {...defaultProps} value={30} />
            );

            expect(screen.getByDisplayValue('30')).toBeInTheDocument();

            rerender(<PageSizeSelector {...defaultProps} value={50} />);

            expect(screen.getByDisplayValue('50')).toBeInTheDocument();
        });
    });
});
