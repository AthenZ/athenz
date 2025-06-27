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
import { renderHook, act } from '@testing-library/react';
import { useMemberFilter } from '../../hooks/useMemberFilter';

describe('useMemberFilter', () => {
    const mockMembers = [
        {
            memberName: 'user.john',
            memberFullName: 'John Doe',
            approved: true,
        },
        {
            memberName: 'user.jane',
            memberFullName: 'Jane Smith',
            approved: true,
        },
        {
            memberName: 'service.api',
            memberFullName: null,
            approved: false,
        },
        {
            memberName: 'user.alice',
            memberFullName: 'Alice Johnson',
            approved: true,
        },
    ];

    describe('initialization', () => {
        it('should initialize with empty filter and all members', () => {
            const { result } = renderHook(() => useMemberFilter(mockMembers));

            expect(result.current.filterText).toBe('');
            expect(result.current.filteredMembers).toEqual(mockMembers);
            expect(result.current.filteredCount).toBe(4);
            expect(result.current.totalCount).toBe(4);
            expect(result.current.hasFilter).toBe(false);
        });

        it('should initialize with provided initial filter', () => {
            const { result } = renderHook(() =>
                useMemberFilter(mockMembers, 'user.john')
            );

            expect(result.current.filterText).toBe('user.john');
            expect(result.current.filteredMembers).toHaveLength(1);
            expect(result.current.filteredMembers[0].memberName).toBe(
                'user.john'
            );
            expect(result.current.hasFilter).toBe(true);
        });
    });

    describe('filtering by member name', () => {
        it('should filter members by memberName (case insensitive)', () => {
            const { result } = renderHook(() => useMemberFilter(mockMembers));

            act(() => {
                result.current.setFilterText('user.john');
            });

            expect(result.current.filteredMembers).toHaveLength(1);
            expect(result.current.filteredMembers[0].memberName).toBe(
                'user.john'
            );
            expect(result.current.filteredCount).toBe(1);
        });

        it('should filter members with partial name match', () => {
            const { result } = renderHook(() => useMemberFilter(mockMembers));

            act(() => {
                result.current.setFilterText('user');
            });

            expect(result.current.filteredMembers).toHaveLength(3);
            expect(
                result.current.filteredMembers.map((m) => m.memberName)
            ).toEqual(['user.john', 'user.jane', 'user.alice']);
        });

        it('should handle case insensitive filtering', () => {
            const { result } = renderHook(() => useMemberFilter(mockMembers));

            act(() => {
                result.current.setFilterText('SERVICE');
            });

            expect(result.current.filteredMembers).toHaveLength(1);
            expect(result.current.filteredMembers[0].memberName).toBe(
                'service.api'
            );
        });
    });

    describe('filtering by member full name', () => {
        it('should filter members by memberFullName', () => {
            const { result } = renderHook(() => useMemberFilter(mockMembers));

            act(() => {
                result.current.setFilterText('Jane Smith');
            });

            expect(result.current.filteredMembers).toHaveLength(1);
            expect(result.current.filteredMembers[0].memberName).toBe(
                'user.jane'
            );
        });

        it('should filter by partial full name match', () => {
            const { result } = renderHook(() => useMemberFilter(mockMembers));

            act(() => {
                result.current.setFilterText('Doe');
            });

            expect(result.current.filteredMembers).toHaveLength(1);
            expect(result.current.filteredMembers[0].memberName).toBe(
                'user.john'
            );
        });

        it('should handle members with null memberFullName', () => {
            const { result } = renderHook(() => useMemberFilter(mockMembers));

            act(() => {
                result.current.setFilterText('api');
            });

            expect(result.current.filteredMembers).toHaveLength(1);
            expect(result.current.filteredMembers[0].memberName).toBe(
                'service.api'
            );
        });
    });

    describe('filter management', () => {
        it('should clear filter correctly', () => {
            const { result } = renderHook(() => useMemberFilter(mockMembers));

            act(() => {
                result.current.setFilterText('john');
            });

            expect(result.current.filteredMembers).toHaveLength(2);
            expect(result.current.hasFilter).toBe(true);

            act(() => {
                result.current.clearFilter();
            });

            expect(result.current.filterText).toBe('');
            expect(result.current.filteredMembers).toEqual(mockMembers);
            expect(result.current.filteredCount).toBe(4);
            expect(result.current.hasFilter).toBe(false);
        });

        it('should handle empty filter text', () => {
            const { result } = renderHook(() => useMemberFilter(mockMembers));

            act(() => {
                result.current.setFilterText('');
            });

            expect(result.current.filteredMembers).toEqual(mockMembers);
            expect(result.current.hasFilter).toBe(false);
        });

        it('should handle whitespace-only filter text', () => {
            const { result } = renderHook(() => useMemberFilter(mockMembers));

            act(() => {
                result.current.setFilterText('   ');
            });

            expect(result.current.filteredMembers).toEqual(mockMembers);
            expect(result.current.hasFilter).toBe(false);
        });
    });

    describe('edge cases', () => {
        it('should handle empty members array', () => {
            const { result } = renderHook(() => useMemberFilter([]));

            expect(result.current.filteredMembers).toEqual([]);
            expect(result.current.filteredCount).toBe(0);
            expect(result.current.totalCount).toBe(0);
        });

        it('should handle filter with no matches', () => {
            const { result } = renderHook(() => useMemberFilter(mockMembers));

            act(() => {
                result.current.setFilterText('nomatch');
            });

            expect(result.current.filteredMembers).toEqual([]);
            expect(result.current.filteredCount).toBe(0);
            expect(result.current.totalCount).toBe(4);
        });

        it('should handle members with missing memberName', () => {
            const membersWithMissingName = [
                { memberFullName: 'Test User', approved: true },
                { memberName: 'user.test', approved: true },
            ];

            const { result } = renderHook(() =>
                useMemberFilter(membersWithMissingName)
            );

            act(() => {
                result.current.setFilterText('test');
            });

            expect(result.current.filteredMembers).toHaveLength(2);
        });
    });

    describe('performance and memoization', () => {
        it('should maintain reference equality when filter unchanged', () => {
            const { result, rerender } = renderHook(() =>
                useMemberFilter(mockMembers)
            );

            const firstResult = result.current.filteredMembers;

            rerender();

            const secondResult = result.current.filteredMembers;
            expect(firstResult).toBe(secondResult);
        });

        it('should update filteredMembers when members change', () => {
            const { result, rerender } = renderHook(
                ({ members }) => useMemberFilter(members),
                { initialProps: { members: mockMembers } }
            );

            act(() => {
                result.current.setFilterText('john');
            });

            expect(result.current.filteredMembers).toHaveLength(2);

            const newMembers = [
                {
                    memberName: 'user.bob',
                    memberFullName: 'Bob Johnson',
                    approved: true,
                },
            ];

            rerender({ members: newMembers });

            expect(result.current.filteredMembers).toHaveLength(1); // Bob Johnson contains 'john'
            expect(result.current.totalCount).toBe(1);
        });
    });
});
