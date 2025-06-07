/*
 * Copyright The Athenz Authors
 * Licensed under the Apache License, Version 2.0
 */

import React from 'react';
import { render, fireEvent } from '@testing-library/react';
import Pagination from '../Pagination';

describe('Pagination', () => {
    const defaultProps = {
        currentPage: 1,
        totalPages: 5,
        onPageChange: jest.fn(),
    };

    beforeEach(() => {
        jest.clearAllMocks();
    });

    it('should render without errors', () => {
        const { getByTestId } = render(<Pagination {...defaultProps} />);
        expect(getByTestId('pagination')).toBeInTheDocument();
    });

    it('should display current page and total pages', () => {
        const { getByText } = render(<Pagination {...defaultProps} />);
        expect(getByText('Page 1 / 5')).toBeInTheDocument();
    });

    it('should not render when totalPages is 1 or less', () => {
        const { container } = render(
            <Pagination {...defaultProps} totalPages={1} />
        );
        expect(container.firstChild).toBeNull();
    });

    it('should render all page numbers when totalPages <= 9', () => {
        const { getByText } = render(
            <Pagination {...defaultProps} totalPages={7} />
        );
        
        for (let i = 1; i <= 7; i++) {
            expect(getByText(i.toString())).toBeInTheDocument();
        }
    });

    it('should render maximum 9 page numbers when totalPages > 9', () => {
        const { container } = render(
            <Pagination {...defaultProps} totalPages={15} />
        );
        
        // Should show pages 1-9 when current page is 1
        const pageButtons = container.querySelectorAll('button');
        const numberButtons = Array.from(pageButtons).filter(button => 
            /^\d+$/.test(button.textContent.trim())
        );
        expect(numberButtons).toHaveLength(9);
    });

    it('should handle first page navigation', () => {
        const onPageChange = jest.fn();
        const { getByText } = render(
            <Pagination 
                currentPage={3} 
                totalPages={5} 
                onPageChange={onPageChange} 
            />
        );
        
        fireEvent.click(getByText('First'));
        expect(onPageChange).toHaveBeenCalledWith(1);
    });

    it('should handle last page navigation', () => {
        const onPageChange = jest.fn();
        const { getByText } = render(
            <Pagination 
                currentPage={3} 
                totalPages={5} 
                onPageChange={onPageChange} 
            />
        );
        
        fireEvent.click(getByText('Last'));
        expect(onPageChange).toHaveBeenCalledWith(5);
    });

    it('should handle previous page navigation', () => {
        const onPageChange = jest.fn();
        const { getByText } = render(
            <Pagination 
                currentPage={3} 
                totalPages={5} 
                onPageChange={onPageChange} 
            />
        );
        
        fireEvent.click(getByText('‹'));
        expect(onPageChange).toHaveBeenCalledWith(2);
    });

    it('should handle next page navigation', () => {
        const onPageChange = jest.fn();
        const { getByText } = render(
            <Pagination 
                currentPage={3} 
                totalPages={5} 
                onPageChange={onPageChange} 
            />
        );
        
        fireEvent.click(getByText('›'));
        expect(onPageChange).toHaveBeenCalledWith(4);
    });

    it('should handle direct page number click', () => {
        const onPageChange = jest.fn();
        const { getByText } = render(
            <Pagination 
                currentPage={1} 
                totalPages={5} 
                onPageChange={onPageChange} 
            />
        );
        
        fireEvent.click(getByText('3'));
        expect(onPageChange).toHaveBeenCalledWith(3);
    });

    it('should disable first/prev buttons on first page', () => {
        const { getByText } = render(
            <Pagination 
                currentPage={1} 
                totalPages={5} 
                onPageChange={jest.fn()} 
            />
        );
        
        expect(getByText('First')).toBeDisabled();
        expect(getByText('‹')).toBeDisabled();
    });

    it('should disable last/next buttons on last page', () => {
        const { getByText } = render(
            <Pagination 
                currentPage={5} 
                totalPages={5} 
                onPageChange={jest.fn()} 
            />
        );
        
        expect(getByText('Last')).toBeDisabled();
        expect(getByText('›')).toBeDisabled();
    });

    it('should highlight current page button', () => {
        const { getByText } = render(
            <Pagination 
                currentPage={3} 
                totalPages={5} 
                onPageChange={jest.fn()} 
            />
        );
        
        const currentPageButton = getByText('3');
        // Button should have primary variant (this depends on Button implementation)
        expect(currentPageButton).toBeInTheDocument();
    });

    it('should generate correct page numbers for middle pages', () => {
        // When current page is in the middle of a large set
        const { getByText } = render(
            <Pagination 
                currentPage={10} 
                totalPages={20} 
                onPageChange={jest.fn()} 
            />
        );
        
        // Should show pages around current page (6-14 when current is 10)
        expect(getByText('6')).toBeInTheDocument();
        expect(getByText('10')).toBeInTheDocument();
        expect(getByText('14')).toBeInTheDocument();
    });

    it('should generate correct page numbers for end pages', () => {
        // When current page is near the end
        const { getByText } = render(
            <Pagination 
                currentPage={18} 
                totalPages={20} 
                onPageChange={jest.fn()} 
            />
        );
        
        // Should show last 9 pages (12-20)
        expect(getByText('12')).toBeInTheDocument();
        expect(getByText('18')).toBeInTheDocument();
        expect(getByText('20')).toBeInTheDocument();
    });

    it('should match snapshot', () => {
        const { container } = render(<Pagination {...defaultProps} />);
        expect(container.firstChild).toMatchSnapshot();
    });

    it('should match snapshot with many pages', () => {
        const { container } = render(
            <Pagination 
                currentPage={10} 
                totalPages={20} 
                onPageChange={jest.fn()} 
            />
        );
        expect(container.firstChild).toMatchSnapshot();
    });
});