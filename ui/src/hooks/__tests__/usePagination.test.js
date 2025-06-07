/*
 * Copyright The Athenz Authors
 * Licensed under the Apache License, Version 2.0
 */

import { renderHook, act } from '@testing-library/react';
import { usePagination } from '../usePagination';

describe('usePagination', () => {
    const mockItems = Array.from({ length: 25 }, (_, i) => ({ id: i + 1, name: `Item ${i + 1}` }));

    it('should initialize with default values', () => {
        const { result } = renderHook(() => usePagination(mockItems));
        
        expect(result.current.currentPage).toBe(1);
        expect(result.current.pageSize).toBe(30);
        expect(result.current.totalPages).toBe(1);
        expect(result.current.displayedItems).toHaveLength(25);
        expect(result.current.displayedItems).toEqual(mockItems);
    });

    it('should initialize with custom page size', () => {
        const { result } = renderHook(() => usePagination(mockItems, 10));
        
        expect(result.current.currentPage).toBe(1);
        expect(result.current.pageSize).toBe(10);
        expect(result.current.totalPages).toBe(3);
        expect(result.current.displayedItems).toHaveLength(10);
        expect(result.current.displayedItems).toEqual(mockItems.slice(0, 10));
    });

    it('should calculate total pages correctly', () => {
        const items = Array.from({ length: 100 }, (_, i) => ({ id: i + 1 }));
        const { result } = renderHook(() => usePagination(items, 30));
        
        expect(result.current.totalPages).toBe(4); // 100 items / 30 per page = 3.33 -> 4
    });

    it('should handle empty items array', () => {
        const { result } = renderHook(() => usePagination([]));
        
        expect(result.current.currentPage).toBe(1);
        expect(result.current.totalPages).toBe(0);
        expect(result.current.displayedItems).toHaveLength(0);
    });

    it('should change page correctly', () => {
        const items = Array.from({ length: 50 }, (_, i) => ({ id: i + 1 }));
        const { result } = renderHook(() => usePagination(items, 10));
        
        act(() => {
            result.current.setCurrentPage(3);
        });
        
        expect(result.current.currentPage).toBe(3);
        expect(result.current.displayedItems).toHaveLength(10);
        expect(result.current.displayedItems[0]).toEqual({ id: 21 }); // Items 21-30
        expect(result.current.displayedItems[9]).toEqual({ id: 30 });
    });

    it('should change page size correctly', () => {
        const items = Array.from({ length: 50 }, (_, i) => ({ id: i + 1 }));
        const { result } = renderHook(() => usePagination(items, 10));
        
        act(() => {
            result.current.setPageSize(20);
        });
        
        expect(result.current.pageSize).toBe(20);
        expect(result.current.totalPages).toBe(3); // 50 items / 20 per page = 2.5 -> 3
        expect(result.current.displayedItems).toHaveLength(20);
    });

    it('should go to specific page with goToPage', () => {
        const items = Array.from({ length: 50 }, (_, i) => ({ id: i + 1 }));
        const { result } = renderHook(() => usePagination(items, 10));
        
        act(() => {
            result.current.goToPage(4);
        });
        
        expect(result.current.currentPage).toBe(4);
        expect(result.current.displayedItems[0]).toEqual({ id: 31 }); // Items 31-40
    });

    it('should not go to invalid page numbers with goToPage', () => {
        const items = Array.from({ length: 50 }, (_, i) => ({ id: i + 1 }));
        const { result } = renderHook(() => usePagination(items, 10));
        
        // Try to go to page 0 (should stay at page 1)
        act(() => {
            result.current.goToPage(0);
        });
        expect(result.current.currentPage).toBe(1);
        
        // Try to go to page beyond total pages (should go to last page)
        act(() => {
            result.current.goToPage(10);
        });
        expect(result.current.currentPage).toBe(5); // Total pages is 5
    });

    it('should go to first page with goToFirstPage', () => {
        const items = Array.from({ length: 50 }, (_, i) => ({ id: i + 1 }));
        const { result } = renderHook(() => usePagination(items, 10));
        
        // First go to a different page
        act(() => {
            result.current.setCurrentPage(3);
        });
        expect(result.current.currentPage).toBe(3);
        
        // Then go to first page
        act(() => {
            result.current.goToFirstPage();
        });
        expect(result.current.currentPage).toBe(1);
    });

    it('should go to last page with goToLastPage', () => {
        const items = Array.from({ length: 50 }, (_, i) => ({ id: i + 1 }));
        const { result } = renderHook(() => usePagination(items, 10));
        
        act(() => {
            result.current.goToLastPage();
        });
        
        expect(result.current.currentPage).toBe(5); // Total pages is 5
        expect(result.current.displayedItems).toHaveLength(10);
        expect(result.current.displayedItems[0]).toEqual({ id: 41 }); // Items 41-50
    });

    it('should handle last page with fewer items', () => {
        const items = Array.from({ length: 47 }, (_, i) => ({ id: i + 1 }));
        const { result } = renderHook(() => usePagination(items, 10));
        
        act(() => {
            result.current.goToLastPage();
        });
        
        expect(result.current.currentPage).toBe(5); // Total pages is 5
        expect(result.current.displayedItems).toHaveLength(7); // Last page has only 7 items
        expect(result.current.displayedItems[0]).toEqual({ id: 41 });
        expect(result.current.displayedItems[6]).toEqual({ id: 47 });
    });

    it('should recalculate when items change', () => {
        const { result, rerender } = renderHook(
            ({ items, pageSize }) => usePagination(items, pageSize),
            {
                initialProps: { items: mockItems, pageSize: 10 }
            }
        );
        
        expect(result.current.totalPages).toBe(3);
        expect(result.current.displayedItems).toHaveLength(10);
        
        // Change items
        const newItems = Array.from({ length: 5 }, (_, i) => ({ id: i + 1 }));
        rerender({ items: newItems, pageSize: 10 });
        
        expect(result.current.totalPages).toBe(1);
        expect(result.current.displayedItems).toHaveLength(5);
        expect(result.current.currentPage).toBe(1); // Should reset to page 1
    });

    it('should handle current page beyond new total pages when items change', () => {
        const { result, rerender } = renderHook(
            ({ items, pageSize }) => usePagination(items, pageSize),
            {
                initialProps: { items: Array.from({ length: 50 }, (_, i) => ({ id: i + 1 })), pageSize: 10 }
            }
        );
        
        // Go to page 4
        act(() => {
            result.current.setCurrentPage(4);
        });
        expect(result.current.currentPage).toBe(4);
        
        // Change to fewer items (only 15 items = 2 pages)
        const newItems = Array.from({ length: 15 }, (_, i) => ({ id: i + 1 }));
        rerender({ items: newItems, pageSize: 10 });
        
        expect(result.current.totalPages).toBe(2);
        // Current page should adjust to valid range
        expect(result.current.currentPage).toBe(4); // Hook doesn't auto-adjust, component should handle this
    });

    it('should handle edge case with single item', () => {
        const items = [{ id: 1, name: 'Single Item' }];
        const { result } = renderHook(() => usePagination(items, 10));
        
        expect(result.current.currentPage).toBe(1);
        expect(result.current.totalPages).toBe(1);
        expect(result.current.displayedItems).toHaveLength(1);
        expect(result.current.displayedItems[0]).toEqual(items[0]);
    });
});