/*
 * Copyright The Athenz Authors
 * Licensed under the Apache License, Version 2.0
 */

import { renderHook, act } from '@testing-library/react';
import { useMemberFilter } from '../useMemberFilter';

describe('useMemberFilter', () => {
    const mockMembers = [
        { memberName: 'alice.smith', fullName: 'Alice Smith' },
        { memberName: 'bob.jones', fullName: 'Bob Jones' },
        { memberName: 'charlie.brown', fullName: 'Charlie Brown' },
        { memberName: 'dave.wilson', fullName: 'Dave Wilson' },
        { memberName: 'eve.davis', fullName: 'Eve Davis' },
    ];

    beforeEach(() => {
        jest.useFakeTimers();
    });

    afterEach(() => {
        jest.runOnlyPendingTimers();
        jest.useRealTimers();
    });

    it('should initialize with all members and empty search', () => {
        const { result } = renderHook(() => useMemberFilter(mockMembers));
        
        expect(result.current.searchText).toBe('');
        expect(result.current.filteredMembers).toEqual(mockMembers);
        expect(result.current.isFiltered).toBe(false);
        expect(result.current.hasResults).toBe(true);
    });

    it('should handle empty members array', () => {
        const { result } = renderHook(() => useMemberFilter([]));
        
        expect(result.current.searchText).toBe('');
        expect(result.current.filteredMembers).toEqual([]);
        expect(result.current.isFiltered).toBe(false);
        expect(result.current.hasResults).toBe(false);
    });

    it('should filter members by memberName with default debounce', () => {
        const { result } = renderHook(() => useMemberFilter(mockMembers));
        
        // Set search text
        act(() => {
            result.current.setSearchText('alice');
        });
        
        // Search text should update immediately
        expect(result.current.searchText).toBe('alice');
        // But filtered members should not update yet (still debouncing)
        expect(result.current.filteredMembers).toEqual(mockMembers);
        expect(result.current.isFiltered).toBe(true); // Based on search text
        
        // Fast-forward debounce time (default 200ms)
        act(() => {
            jest.advanceTimersByTime(200);
        });
        
        // Now filtered members should update
        expect(result.current.filteredMembers).toEqual([
            { memberName: 'alice.smith', fullName: 'Alice Smith' }
        ]);
        expect(result.current.hasResults).toBe(true);
    });

    it('should filter members case-insensitively', () => {
        const { result } = renderHook(() => useMemberFilter(mockMembers));
        
        act(() => {
            result.current.setSearchText('ALICE');
        });
        
        act(() => {
            jest.advanceTimersByTime(200);
        });
        
        expect(result.current.filteredMembers).toEqual([
            { memberName: 'alice.smith', fullName: 'Alice Smith' }
        ]);
    });

    it('should filter members with partial matches', () => {
        const { result } = renderHook(() => useMemberFilter(mockMembers));
        
        act(() => {
            result.current.setSearchText('smith');
        });
        
        act(() => {
            jest.advanceTimersByTime(200);
        });
        
        expect(result.current.filteredMembers).toEqual([
            { memberName: 'alice.smith', fullName: 'Alice Smith' }
        ]);
    });

    it('should return multiple matches', () => {
        const { result } = renderHook(() => useMemberFilter(mockMembers));
        
        act(() => {
            result.current.setSearchText('o'); // Should match bob.jones, charlie.brown, and dave.wilson
        });
        
        act(() => {
            jest.advanceTimersByTime(200);
        });
        
        expect(result.current.filteredMembers).toHaveLength(3);
        expect(result.current.filteredMembers).toEqual([
            { memberName: 'bob.jones', fullName: 'Bob Jones' },
            { memberName: 'charlie.brown', fullName: 'Charlie Brown' },
            { memberName: 'dave.wilson', fullName: 'Dave Wilson' }
        ]);
    });

    it('should return empty array for no matches', () => {
        const { result } = renderHook(() => useMemberFilter(mockMembers));
        
        act(() => {
            result.current.setSearchText('xyz');
        });
        
        act(() => {
            jest.advanceTimersByTime(200);
        });
        
        expect(result.current.filteredMembers).toEqual([]);
        expect(result.current.hasResults).toBe(false);
        expect(result.current.isFiltered).toBe(true);
    });

    it('should reset to all members when search is cleared', () => {
        const { result } = renderHook(() => useMemberFilter(mockMembers));
        
        // First filter
        act(() => {
            result.current.setSearchText('alice');
        });
        
        act(() => {
            jest.advanceTimersByTime(200);
        });
        
        expect(result.current.filteredMembers).toHaveLength(1);
        
        // Clear search
        act(() => {
            result.current.setSearchText('');
        });
        
        act(() => {
            jest.advanceTimersByTime(200);
        });
        
        expect(result.current.filteredMembers).toEqual(mockMembers);
        expect(result.current.isFiltered).toBe(false);
        expect(result.current.hasResults).toBe(true);
    });

    it('should handle whitespace-only search text', () => {
        const { result } = renderHook(() => useMemberFilter(mockMembers));
        
        act(() => {
            result.current.setSearchText('   ');
        });
        
        act(() => {
            jest.advanceTimersByTime(200);
        });
        
        expect(result.current.filteredMembers).toEqual(mockMembers);
        expect(result.current.isFiltered).toBe(true); // Search text is not empty, even if trimmed
        expect(result.current.hasResults).toBe(true);
    });

    it('should use custom debounce time', () => {
        const { result } = renderHook(() => useMemberFilter(mockMembers, 500));
        
        act(() => {
            result.current.setSearchText('alice');
        });
        
        // Should not update after default 200ms
        act(() => {
            jest.advanceTimersByTime(200);
        });
        expect(result.current.filteredMembers).toEqual(mockMembers);
        
        // Should update after custom 500ms
        act(() => {
            jest.advanceTimersByTime(300); // Total 500ms
        });
        expect(result.current.filteredMembers).toHaveLength(1);
    });

    it('should debounce rapid search changes', () => {
        const { result } = renderHook(() => useMemberFilter(mockMembers));
        
        // Rapid changes
        act(() => {
            result.current.setSearchText('a');
        });
        
        act(() => {
            jest.advanceTimersByTime(100);
        });
        
        act(() => {
            result.current.setSearchText('al');
        });
        
        act(() => {
            jest.advanceTimersByTime(100);
        });
        
        act(() => {
            result.current.setSearchText('alice');
        });
        
        // Should not have updated yet
        expect(result.current.filteredMembers).toEqual(mockMembers);
        
        // Complete debounce
        act(() => {
            jest.advanceTimersByTime(200);
        });
        
        // Should filter based on final search text
        expect(result.current.filteredMembers).toEqual([
            { memberName: 'alice.smith', fullName: 'Alice Smith' }
        ]);
    });

    it('should update when members prop changes', () => {
        const { result, rerender } = renderHook(
            ({ members, debounceTime }) => useMemberFilter(members, debounceTime),
            {
                initialProps: { members: mockMembers, debounceTime: 200 }
            }
        );
        
        expect(result.current.filteredMembers).toEqual(mockMembers);
        
        // Change members
        const newMembers = [
            { memberName: 'new.user', fullName: 'New User' }
        ];
        act(() => {
            rerender({ members: newMembers, debounceTime: 200 });
        });
        
        expect(result.current.filteredMembers).toEqual(newMembers);
    });

    it('should maintain search text when members change', () => {
        const { result, rerender } = renderHook(
            ({ members, debounceTime }) => useMemberFilter(members, debounceTime),
            {
                initialProps: { members: mockMembers, debounceTime: 200 }
            }
        );
        
        // Set search text
        act(() => {
            result.current.setSearchText('alice');
        });
        
        expect(result.current.searchText).toBe('alice');
        
        // Change members
        const newMembers = [
            { memberName: 'alice.new', fullName: 'Alice New' },
            { memberName: 'bob.new', fullName: 'Bob New' }
        ];
        act(() => {
            rerender({ members: newMembers, debounceTime: 200 });
        });
        
        // Search text should be maintained
        expect(result.current.searchText).toBe('alice');
        
        // Fast-forward to complete debounce
        act(() => {
            jest.advanceTimersByTime(200);
        });
        
        // Should filter new members with existing search
        expect(result.current.filteredMembers).toEqual([
            { memberName: 'alice.new', fullName: 'Alice New' }
        ]);
    });

    it('should handle undefined members gracefully', () => {
        const { result } = renderHook(() => useMemberFilter(undefined));
        
        expect(result.current.filteredMembers).toEqual([]);
        expect(result.current.hasResults).toBe(false);
        expect(result.current.isFiltered).toBe(false);
    });
});