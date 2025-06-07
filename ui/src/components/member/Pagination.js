/*
 * Copyright The Athenz Authors
 * Licensed under the Apache License, Version 2.0
 */

import React from 'react';
import PropTypes from 'prop-types';
import styled from '@emotion/styled';
import Button from '../denali/Button';
import { colors } from '../denali/styles';

const PaginationContainer = styled.div`
    display: flex;
    align-items: center;
    justify-content: space-between;
    margin: 15px 0;
    padding: 10px 0;
    border-top: 1px solid ${colors.grey300};
`;

const PageInfo = styled.span`
    color: ${colors.grey700};
    font-size: 14px;
    font-weight: 500;
`;

const PageButtons = styled.div`
    display: flex;
    gap: 5px;
    align-items: center;
`;

const PageButton = styled(Button)`
    min-width: 36px;
    height: 32px;
    padding: 0 8px;
`;

export default class Pagination extends React.Component {
    generatePageNumbers() {
        const { currentPage, totalPages } = this.props;
        const maxVisible = 9;
        
        if (totalPages <= maxVisible) {
            return Array.from({ length: totalPages }, (_, i) => i + 1);
        }
        
        // Dynamic page number logic for max 9 pages
        const start = Math.max(1, Math.min(currentPage - 4, totalPages - maxVisible + 1));
        const end = Math.min(totalPages, start + maxVisible - 1);
        
        return Array.from({ length: end - start + 1 }, (_, i) => start + i);
    }
    
    render() {
        const { currentPage, totalPages, onPageChange } = this.props;
        
        if (totalPages <= 1) {
            return null;
        }
        
        const pageNumbers = this.generatePageNumbers();
        
        return (
            <PaginationContainer data-testid="pagination">
                <PageInfo>
                    Page {currentPage} / {totalPages}
                </PageInfo>
                
                <PageButtons>
                    <PageButton 
                        disabled={currentPage === 1}
                        onClick={() => onPageChange(1)}
                        size="small"
                        variant="secondary"
                    >
                        First
                    </PageButton>
                    
                    <PageButton
                        disabled={currentPage === 1}
                        onClick={() => onPageChange(currentPage - 1)}
                        size="small"
                        variant="secondary"
                    >
                        ‹
                    </PageButton>
                    
                    {pageNumbers.map(pageNumber => (
                        <PageButton
                            key={pageNumber}
                            variant={currentPage === pageNumber ? 'primary' : 'secondary'}
                            onClick={() => onPageChange(pageNumber)}
                            size="small"
                        >
                            {pageNumber}
                        </PageButton>
                    ))}
                    
                    <PageButton
                        disabled={currentPage === totalPages}
                        onClick={() => onPageChange(currentPage + 1)}
                        size="small"
                        variant="secondary"
                    >
                        ›
                    </PageButton>
                    
                    <PageButton 
                        disabled={currentPage === totalPages}
                        onClick={() => onPageChange(totalPages)}
                        size="small"
                        variant="secondary"
                    >
                        Last
                    </PageButton>
                </PageButtons>
            </PaginationContainer>
        );
    }
}

Pagination.propTypes = {
    /** Current page number */
    currentPage: PropTypes.number.isRequired,
    /** Total number of pages */
    totalPages: PropTypes.number.isRequired,
    /** Page change handler */
    onPageChange: PropTypes.func.isRequired,
};