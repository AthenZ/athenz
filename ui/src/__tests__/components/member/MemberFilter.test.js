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
import MemberFilter from '../../../components/member/MemberFilter';

describe('MemberFilter', () => {
    const defaultProps = {
        value: '',
        onChange: jest.fn(),
        testId: 'member-filter',
    };

    beforeEach(() => {
        jest.clearAllMocks();
    });

    describe('rendering', () => {
        it('should render filter input with placeholder', () => {
            render(<MemberFilter {...defaultProps} />);

            const input = screen.getByPlaceholderText('Filter members by name');
            expect(input).toBeInTheDocument();
            expect(input).toHaveAttribute(
                'aria-label',
                'Filter members by name'
            );
        });

        it('should update aria-label when filter is active', () => {
            render(<MemberFilter {...defaultProps} value='test' />);

            const input = screen.getByPlaceholderText('Filter members by name');
            expect(input).toHaveAttribute(
                'aria-label',
                'Filter members by name (filtered)'
            );
        });
    });

    describe('interactions', () => {
        it('should call onChange when input value changes', () => {
            render(<MemberFilter {...defaultProps} />);

            const input = screen.getByPlaceholderText('Filter members by name');
            fireEvent.change(input, { target: { value: 'test' } });

            expect(defaultProps.onChange).toHaveBeenCalledWith('test');
        });

        it('should clear filter when Escape key is pressed with filter', () => {
            render(<MemberFilter {...defaultProps} value='test' />);

            const input = screen.getByPlaceholderText('Filter members by name');
            fireEvent.keyDown(input, { key: 'Escape' });

            expect(defaultProps.onChange).toHaveBeenCalledWith('');
        });

        it('should not clear filter when Escape key is pressed without filter', () => {
            render(<MemberFilter {...defaultProps} />);

            const input = screen.getByPlaceholderText('Filter members by name');
            fireEvent.keyDown(input, { key: 'Escape' });

            expect(defaultProps.onChange).not.toHaveBeenCalled();
        });

        it('should handle keyboard navigation properly', () => {
            render(<MemberFilter {...defaultProps} />);

            const input = screen.getByPlaceholderText('Filter members by name');
            fireEvent.keyDown(input, { key: 'Enter' });
            fireEvent.keyDown(input, { key: 'Tab' });

            // Should not crash and input should still be functional
            expect(input).toBeInTheDocument();
        });
    });

    describe('accessibility', () => {
        it('should have proper ARIA attributes', () => {
            render(<MemberFilter {...defaultProps} />);

            const input = screen.getByPlaceholderText('Filter members by name');
            expect(input).toHaveAttribute(
                'aria-label',
                'Filter members by name'
            );
        });

        it('should update aria-label based on filter state', () => {
            const { rerender } = render(<MemberFilter {...defaultProps} />);

            let input = screen.getByPlaceholderText('Filter members by name');
            expect(input).toHaveAttribute(
                'aria-label',
                'Filter members by name'
            );

            rerender(<MemberFilter {...defaultProps} value='test' />);

            input = screen.getByPlaceholderText('Filter members by name');
            expect(input).toHaveAttribute(
                'aria-label',
                'Filter members by name (filtered)'
            );
        });
    });

    describe('disabled state', () => {
        it('should disable input when disabled prop is true', () => {
            render(<MemberFilter {...defaultProps} disabled={true} />);

            const input = screen.getByPlaceholderText('Filter members by name');
            expect(input).toBeDisabled();
        });
    });

    describe('edge cases', () => {
        it('should handle missing onChange gracefully', () => {
            const { onChange, ...propsWithoutOnChange } = defaultProps;
            render(<MemberFilter {...propsWithoutOnChange} />);

            const input = screen.getByPlaceholderText('Filter members by name');
            expect(() => {
                fireEvent.change(input, { target: { value: 'test' } });
            }).not.toThrow();
        });

        it('should render without testId', () => {
            const { testId, ...propsWithoutTestId } = defaultProps;
            render(<MemberFilter {...propsWithoutTestId} />);

            const input = screen.getByPlaceholderText('Filter members by name');
            expect(input).toBeInTheDocument();
        });
    });

    describe('styling and layout', () => {
        it('should apply proper test IDs', () => {
            render(<MemberFilter {...defaultProps} />);

            expect(screen.getByTestId('member-filter')).toBeInTheDocument();

            // SearchInput uses its own internal testIds
            expect(screen.getByTestId('input-node')).toBeInTheDocument();
        });
    });
});
