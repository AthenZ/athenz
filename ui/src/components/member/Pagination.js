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
import styled from '@emotion/styled';
import { colors } from '../denali/styles';
import Icon from '../denali/icons/Icon';
import {
    PAGINATION_SHOWING_TEXT,
    PAGINATION_OF_TEXT,
    PAGINATION_PREVIOUS_TEXT,
    PAGINATION_NEXT_TEXT,
    PAGINATION_ARIA_PREVIOUS_LABEL,
    PAGINATION_ARIA_NEXT_LABEL,
    PAGINATION_ARIA_PAGE_LABEL,
    PAGINATION_ARIA_CURRENT_PAGE,
    PAGINATION_ARIA_ROLE_BUTTON,
} from '../constants/constants';

const PaginationContainer = styled.div`
    display: flex;
    flex-direction: column;
    align-items: center;
    gap: 8px;
    margin: ${(props) => (props.inTable ? '0' : '20px 0')};
    color: inherit;
`;

const InfoText = styled.div`
    color: ${colors.grey600};
    font-size: 14px;
    font-weight: normal;
    text-align: center;
`;

const PaginationControls = styled.div`
    display: flex;
    align-items: center;
    gap: 8px;
`;

const NavigationButtonStyle = styled.button`
    min-width: 80px !important;
    gap: 8px;
`;

const Ellipsis = styled.span`
    color: ${colors.grey600};
    padding: 8px 4px;
    font-size: 14px;
    display: flex;
    align-items: center;
    align-self: center;
`;

/**
 * Generic Pagination component with Denali Design System compliance
 *
 * @param {number} currentPage - Current active page (1-indexed)
 * @param {number} totalPages - Total number of pages
 * @param {number} totalItems - Total number of items across all pages
 * @param {function} onPageChange - Callback when page number is clicked
 * @param {function} onNextPage - Callback for next button
 * @param {function} onPreviousPage - Callback for previous button
 * @param {boolean} showInfo - Whether to show "Showing X-Y of Z items" text
 * @param {boolean} compact - Whether to use compact mode (no page numbers)
 * @param {number} itemsPerPage - Number of items per page for display calculation
 * @param {string} itemType - Type of items being paginated (e.g., 'members', 'roles', 'policies')
 * @param {string} memberType - Deprecated: use itemType instead
 * @param {string} className - Additional CSS classes
 * @param {boolean} inTable - Whether pagination is inside a table (affects styling)
 */
const Pagination = ({
    currentPage,
    totalPages,
    totalItems,
    onPageChange,
    onNextPage,
    onPreviousPage,
    showInfo = true,
    compact = false,
    itemsPerPage = 10,
    itemType,
    memberType = 'members', // Deprecated: use itemType instead
    className,
    inTable = false,
}) => {
    // Backward compatibility: use itemType if provided, otherwise fall back to memberType
    const displayItemType = itemType || memberType;

    const startItem =
        totalItems === 0 ? 0 : (currentPage - 1) * itemsPerPage + 1;
    const endItem = Math.min(currentPage * itemsPerPage, totalItems);

    const hasPrevious = currentPage > 1;
    const hasNext = currentPage < totalPages;

    const handlePageClick = (page, event) => {
        if (page !== currentPage && onPageChange) {
            onPageChange(page);
            // Remove focus to reset hover state after click (Denali best practice)
            if (event && event.target) {
                event.target.blur();
            }
        }
    };

    const handlePreviousClick = (event) => {
        if (hasPrevious && onPreviousPage) {
            onPreviousPage();
            // Remove focus to reset hover state after click (Denali best practice)
            if (event && event.target && event.target.blur) {
                event.target.blur();
            }
        }
    };

    const handleNextClick = (event) => {
        if (hasNext && onNextPage) {
            onNextPage();
            // Remove focus to reset hover state after click (Denali best practice)
            if (event && event.target && event.target.blur) {
                event.target.blur();
            }
        }
    };

    const handleKeyDown = (event, action) => {
        if (event.key === 'Enter' || event.key === ' ') {
            event.preventDefault();
            action();
            // Remove focus to reset hover state after keyboard activation (Denali best practice)
            if (event && event.target && event.target.blur) {
                event.target.blur();
            }
        }
    };

    const getVisiblePages = () => {
        if (totalPages <= 7) {
            return Array.from({ length: totalPages }, (_, i) => i + 1);
        }

        const pages = [];

        if (currentPage <= 4) {
            pages.push(1, 2, 3, 4, 5, '...', totalPages);
        } else if (currentPage >= totalPages - 3) {
            pages.push(
                1,
                '...',
                totalPages - 4,
                totalPages - 3,
                totalPages - 2,
                totalPages - 1,
                totalPages
            );
        } else {
            pages.push(
                1,
                '...',
                currentPage - 2,
                currentPage - 1,
                currentPage,
                currentPage + 1,
                currentPage + 2,
                '...',
                totalPages
            );
        }

        return pages;
    };

    const visiblePages = compact ? [] : getVisiblePages();

    return (
        <PaginationContainer className={className} inTable={inTable}>
            {showInfo && (
                <InfoText inTable={inTable}>
                    {PAGINATION_SHOWING_TEXT} {startItem}-{endItem}{' '}
                    {PAGINATION_OF_TEXT} {totalItems} {displayItemType}
                </InfoText>
            )}

            <PaginationControls>
                <NavigationButtonStyle
                    className='button is-outline is-small'
                    disabled={!hasPrevious}
                    onClick={handlePreviousClick}
                    onKeyDown={(e) => handleKeyDown(e, handlePreviousClick)}
                    aria-label={PAGINATION_ARIA_PREVIOUS_LABEL}
                >
                    <Icon icon='arrow-left' size='1em' color='currentColor' />
                    {PAGINATION_PREVIOUS_TEXT}
                </NavigationButtonStyle>

                {!compact && visiblePages.length > 0 && (
                    <div className='toggle is-small'>
                        <ul>
                            {visiblePages.map((page, index) =>
                                page === '...' ? (
                                    <Ellipsis key={`ellipsis-${index}`}>
                                        ...
                                    </Ellipsis>
                                ) : (
                                    <li
                                        key={page}
                                        className={
                                            page === currentPage
                                                ? 'is-active'
                                                : ''
                                        }
                                        onClick={(event) =>
                                            handlePageClick(page, event)
                                        }
                                        onKeyDown={(e) =>
                                            handleKeyDown(e, () =>
                                                handlePageClick(page, e)
                                            )
                                        }
                                        aria-label={`${PAGINATION_ARIA_PAGE_LABEL} ${page}`}
                                        aria-current={
                                            page === currentPage
                                                ? PAGINATION_ARIA_CURRENT_PAGE
                                                : undefined
                                        }
                                        role={PAGINATION_ARIA_ROLE_BUTTON}
                                        tabIndex={0}
                                    >
                                        <a>{page}</a>
                                    </li>
                                )
                            )}
                        </ul>
                    </div>
                )}

                <NavigationButtonStyle
                    className='button is-outline is-small'
                    disabled={!hasNext}
                    onClick={handleNextClick}
                    onKeyDown={(e) => handleKeyDown(e, handleNextClick)}
                    aria-label={PAGINATION_ARIA_NEXT_LABEL}
                >
                    {PAGINATION_NEXT_TEXT}
                    <Icon icon='arrow-right' size='1em' color='currentColor' />
                </NavigationButtonStyle>
            </PaginationControls>
        </PaginationContainer>
    );
};

export default Pagination;
