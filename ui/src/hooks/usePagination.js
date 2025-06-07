/*
 * Copyright The Athenz Authors
 * Licensed under the Apache License, Version 2.0
 */

import { useState, useMemo } from 'react';

/**
 * Custom hook for pagination functionality
 * @param {Array} items - Array of items to paginate
 * @param {number} initialPageSize - Initial page size (default: 30)
 * @returns {Object} - Pagination state and controls
 */
export const usePagination = (items, initialPageSize = 30) => {
    const [currentPage, setCurrentPage] = useState(1);
    const [pageSize, setPageSize] = useState(initialPageSize);

    // Calculate total pages
    const totalPages = useMemo(() => {
        return Math.ceil((items?.length || 0) / pageSize);
    }, [items?.length, pageSize]);

    // Calculate displayed items for current page
    const displayedItems = useMemo(() => {
        if (!items || items.length === 0) {
            return [];
        }
        
        const startIndex = (currentPage - 1) * pageSize;
        const endIndex = startIndex + pageSize;
        return items.slice(startIndex, endIndex);
    }, [items, currentPage, pageSize]);

    // Navigation functions
    const goToPage = (page) => {
        const validPage = Math.min(Math.max(1, page), totalPages);
        setCurrentPage(validPage);
    };

    const goToFirstPage = () => {
        setCurrentPage(1);
    };

    const goToLastPage = () => {
        setCurrentPage(totalPages);
    };

    return {
        currentPage,
        pageSize,
        totalPages,
        displayedItems,
        setCurrentPage,
        setPageSize,
        goToPage,
        goToFirstPage,
        goToLastPage,
    };
};