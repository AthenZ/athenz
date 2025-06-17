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
import Pagination from '../../../components/member/Pagination';

describe('Pagination', () => {
    const defaultProps = {
        currentPage: 1,
        totalPages: 5,
        totalItems: 50,
        onPageChange: jest.fn(),
        onNextPage: jest.fn(),
        onPreviousPage: jest.fn(),
    };

    beforeEach(() => {
        jest.clearAllMocks();
    });

    describe('rendering', () => {
        it('should render pagination component', () => {
            render(<Pagination {...defaultProps} />);

            expect(
                screen.getByText('Showing 1-10 of 50 members')
            ).toBeInTheDocument();
            expect(
                screen.getByRole('button', { name: /previous/i })
            ).toBeInTheDocument();
            expect(
                screen.getByRole('button', { name: /next/i })
            ).toBeInTheDocument();
        });

        it('should render page numbers', () => {
            render(<Pagination {...defaultProps} />);

            expect(
                screen.getByRole('button', { name: 'Page 1' })
            ).toBeInTheDocument();
            expect(
                screen.getByRole('button', { name: 'Page 2' })
            ).toBeInTheDocument();
            expect(
                screen.getByRole('button', { name: 'Page 3' })
            ).toBeInTheDocument();
            expect(
                screen.getByRole('button', { name: 'Page 4' })
            ).toBeInTheDocument();
            expect(
                screen.getByRole('button', { name: 'Page 5' })
            ).toBeInTheDocument();
        });

        it('should highlight current page', () => {
            render(<Pagination {...defaultProps} currentPage={3} />);

            const currentPageButton = screen.getByRole('button', {
                name: 'Page 3',
            });
            expect(currentPageButton).toHaveAttribute('aria-current', 'page');
        });

        it('should show correct info text for different page ranges', () => {
            const { rerender } = render(
                <Pagination {...defaultProps} currentPage={2} />
            );
            expect(
                screen.getByText('Showing 11-20 of 50 members')
            ).toBeInTheDocument();

            rerender(<Pagination {...defaultProps} currentPage={5} />);
            expect(
                screen.getByText('Showing 41-50 of 50 members')
            ).toBeInTheDocument();
        });

        it('should handle partial last page correctly', () => {
            render(
                <Pagination
                    {...defaultProps}
                    totalItems={47}
                    totalPages={5}
                    currentPage={5}
                />
            );

            expect(
                screen.getByText('Showing 41-47 of 47 members')
            ).toBeInTheDocument();
        });

        it('should render without page info when showInfo is false', () => {
            render(<Pagination {...defaultProps} showInfo={false} />);

            expect(screen.queryByText(/showing/i)).not.toBeInTheDocument();
        });

        it('should render in compact mode', () => {
            render(<Pagination {...defaultProps} compact={true} />);

            // In compact mode, only previous/next buttons should be visible
            expect(
                screen.getByRole('button', { name: /previous/i })
            ).toBeInTheDocument();
            expect(
                screen.getByRole('button', { name: /next/i })
            ).toBeInTheDocument();
            expect(
                screen.queryByRole('button', { name: 'Page 1' })
            ).not.toBeInTheDocument();
        });
    });

    describe('button states', () => {
        it('should disable previous button on first page', () => {
            render(<Pagination {...defaultProps} currentPage={1} />);

            const previousButton = screen.getByRole('button', {
                name: /previous/i,
            });
            expect(previousButton).toBeDisabled();
        });

        it('should disable next button on last page', () => {
            render(<Pagination {...defaultProps} currentPage={5} />);

            const nextButton = screen.getByRole('button', { name: /next/i });
            expect(nextButton).toBeDisabled();
        });

        it('should enable both buttons on middle pages', () => {
            render(<Pagination {...defaultProps} currentPage={3} />);

            const previousButton = screen.getByRole('button', {
                name: /previous/i,
            });
            const nextButton = screen.getByRole('button', { name: /next/i });

            expect(previousButton).toBeEnabled();
            expect(nextButton).toBeEnabled();
        });
    });

    describe('page number truncation', () => {
        const manyPagesProps = {
            ...defaultProps,
            totalPages: 20,
            totalItems: 200,
        };

        it('should show truncated pages when there are many pages', () => {
            render(<Pagination {...manyPagesProps} currentPage={1} />);

            expect(
                screen.getByRole('button', { name: 'Page 1' })
            ).toBeInTheDocument();
            expect(
                screen.getByRole('button', { name: 'Page 2' })
            ).toBeInTheDocument();
            expect(
                screen.getByRole('button', { name: 'Page 3' })
            ).toBeInTheDocument();
            expect(screen.getByText('...')).toBeInTheDocument();
            expect(
                screen.getByRole('button', { name: 'Page 20' })
            ).toBeInTheDocument();
        });

        it('should show correct pages when current page is in middle', () => {
            render(<Pagination {...manyPagesProps} currentPage={10} />);

            expect(
                screen.getByRole('button', { name: 'Page 1' })
            ).toBeInTheDocument();
            expect(screen.getAllByText('...')).toHaveLength(2);
            expect(
                screen.getByRole('button', { name: 'Page 8' })
            ).toBeInTheDocument();
            expect(
                screen.getByRole('button', { name: 'Page 9' })
            ).toBeInTheDocument();
            expect(
                screen.getByRole('button', { name: 'Page 10' })
            ).toBeInTheDocument();
            expect(
                screen.getByRole('button', { name: 'Page 11' })
            ).toBeInTheDocument();
            expect(
                screen.getByRole('button', { name: 'Page 12' })
            ).toBeInTheDocument();
            expect(
                screen.getByRole('button', { name: 'Page 20' })
            ).toBeInTheDocument();
        });

        it('should show correct pages when current page is near end', () => {
            render(<Pagination {...manyPagesProps} currentPage={18} />);

            expect(
                screen.getByRole('button', { name: 'Page 1' })
            ).toBeInTheDocument();
            expect(screen.getByText('...')).toBeInTheDocument();
            expect(
                screen.getByRole('button', { name: 'Page 16' })
            ).toBeInTheDocument();
            expect(
                screen.getByRole('button', { name: 'Page 17' })
            ).toBeInTheDocument();
            expect(
                screen.getByRole('button', { name: 'Page 18' })
            ).toBeInTheDocument();
            expect(
                screen.getByRole('button', { name: 'Page 19' })
            ).toBeInTheDocument();
            expect(
                screen.getByRole('button', { name: 'Page 20' })
            ).toBeInTheDocument();
        });
    });

    describe('interactions', () => {
        it('should call onPreviousPage when previous button is clicked', () => {
            render(<Pagination {...defaultProps} currentPage={3} />);

            const previousButton = screen.getByRole('button', {
                name: /previous/i,
            });
            fireEvent.click(previousButton);

            expect(defaultProps.onPreviousPage).toHaveBeenCalledTimes(1);
        });

        it('should call onNextPage when next button is clicked', () => {
            render(<Pagination {...defaultProps} currentPage={3} />);

            const nextButton = screen.getByRole('button', { name: /next/i });
            fireEvent.click(nextButton);

            expect(defaultProps.onNextPage).toHaveBeenCalledTimes(1);
        });

        it('should call onPageChange when page number is clicked', () => {
            render(<Pagination {...defaultProps} />);

            const pageButton = screen.getByRole('button', { name: 'Page 3' });
            fireEvent.click(pageButton);

            expect(defaultProps.onPageChange).toHaveBeenCalledWith(3);
        });

        it('should not call callbacks when buttons are disabled', () => {
            render(<Pagination {...defaultProps} currentPage={1} />);

            const previousButton = screen.getByRole('button', {
                name: /previous/i,
            });
            fireEvent.click(previousButton);

            expect(defaultProps.onPreviousPage).not.toHaveBeenCalled();
        });
    });

    describe('keyboard navigation', () => {
        it('should handle keyboard navigation on page buttons', () => {
            render(<Pagination {...defaultProps} />);

            const pageButton = screen.getByRole('button', { name: 'Page 2' });
            fireEvent.keyDown(pageButton, { key: 'Enter' });

            expect(defaultProps.onPageChange).toHaveBeenCalledWith(2);
        });

        it('should handle keyboard navigation on previous button', () => {
            render(<Pagination {...defaultProps} currentPage={2} />);

            const previousButton = screen.getByRole('button', {
                name: /previous/i,
            });
            fireEvent.keyDown(previousButton, { key: 'Enter' });

            expect(defaultProps.onPreviousPage).toHaveBeenCalledTimes(1);
        });

        it('should handle keyboard navigation on next button', () => {
            render(<Pagination {...defaultProps} currentPage={2} />);

            const nextButton = screen.getByRole('button', { name: /next/i });
            fireEvent.keyDown(nextButton, { key: 'Enter' });

            expect(defaultProps.onNextPage).toHaveBeenCalledTimes(1);
        });
    });

    describe('edge cases', () => {
        it('should render correctly with single page', () => {
            render(
                <Pagination
                    {...defaultProps}
                    totalPages={1}
                    currentPage={1}
                    totalItems={5}
                />
            );

            expect(
                screen.getByText('Showing 1-5 of 5 members')
            ).toBeInTheDocument();
            expect(
                screen.getByRole('button', { name: /previous/i })
            ).toBeDisabled();
            expect(
                screen.getByRole('button', { name: /next/i })
            ).toBeDisabled();
            expect(
                screen.getByRole('button', { name: 'Page 1' })
            ).toBeInTheDocument();
        });

        it('should render correctly with zero pages', () => {
            render(
                <Pagination
                    {...defaultProps}
                    totalPages={0}
                    currentPage={1}
                    totalItems={0}
                />
            );

            expect(
                screen.getByText('Showing 0-0 of 0 members')
            ).toBeInTheDocument();
            expect(
                screen.getByRole('button', { name: /previous/i })
            ).toBeDisabled();
            expect(
                screen.getByRole('button', { name: /next/i })
            ).toBeDisabled();
        });

        it('should handle invalid current page gracefully', () => {
            render(
                <Pagination {...defaultProps} currentPage={10} totalPages={5} />
            );

            // Should still render without crashing, but with correct calculation
            expect(
                screen.getByText('Showing 91-50 of 50 members')
            ).toBeInTheDocument();
        });
    });

    describe('custom props', () => {
        it('should use custom items per page for calculations', () => {
            render(
                <Pagination
                    {...defaultProps}
                    itemsPerPage={25}
                    totalItems={75}
                />
            );

            expect(
                screen.getByText('Showing 1-25 of 75 members')
            ).toBeInTheDocument();
        });

        it('should use custom member type text', () => {
            render(<Pagination {...defaultProps} memberType='users' />);

            expect(
                screen.getByText('Showing 1-10 of 50 users')
            ).toBeInTheDocument();
        });

        it('should apply custom CSS classes', () => {
            const { container } = render(
                <Pagination {...defaultProps} className='custom-pagination' />
            );

            expect(container.firstChild).toHaveClass('custom-pagination');
        });
    });
});
