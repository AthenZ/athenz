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
import { useMemberPagination } from '../../hooks/useMemberPagination';

describe('useMemberPagination', () => {
    const sampleMembers = [
        {
            memberName: 'user.alice',
            memberFullName: 'Alice Smith',
            approved: true,
        },
        { memberName: 'user.bob', memberFullName: 'Bob Jones', approved: true },
        {
            memberName: 'user.carol',
            memberFullName: 'Carol Brown',
            approved: false,
        },
        {
            memberName: 'user.dave',
            memberFullName: 'Dave Wilson',
            approved: true,
        },
        {
            memberName: 'user.eve',
            memberFullName: 'Eve Davis',
            approved: false,
        },
        {
            memberName: 'user.frank',
            memberFullName: 'Frank Miller',
            approved: true,
        },
    ];

    const collectionDetails = { trust: false };
    const trustCollectionDetails = { trust: true };

    describe('initial state', () => {
        it('should initialize with default values', () => {
            const { result } = renderHook(() =>
                useMemberPagination(sampleMembers, collectionDetails, true)
            );

            expect(result.current.paginationEnabled).toBe(true);
            expect(result.current.totalMembersCount).toBe(6);
            expect(result.current.filteredMembersCount).toBe(6);
            expect(result.current.approvedMembers.totalItems).toBe(4);
            expect(result.current.pendingMembers.totalItems).toBe(2);
        });

        it('should handle trust collections correctly', () => {
            const { result } = renderHook(() =>
                useMemberPagination(sampleMembers, trustCollectionDetails, true)
            );

            expect(result.current.approvedMembers.totalItems).toBe(6);
            expect(result.current.pendingMembers.totalItems).toBe(0);
        });

        it('should handle disabled pagination', () => {
            const { result } = renderHook(() =>
                useMemberPagination(sampleMembers, collectionDetails, false)
            );

            expect(result.current.paginationEnabled).toBe(false);
            expect(result.current.approvedMembers.data).toHaveLength(4);
            expect(result.current.pendingMembers.data).toHaveLength(2);
            expect(result.current.approvedMembers.showPagination).toBe(false);
        });
    });

    describe('filtering', () => {
        it('should filter members by name', () => {
            const { result } = renderHook(() =>
                useMemberPagination(sampleMembers, collectionDetails, true)
            );

            act(() => {
                result.current.setFilterText('alice');
            });

            expect(result.current.filteredMembersCount).toBe(1);
            expect(result.current.approvedMembers.totalItems).toBe(1);
            expect(result.current.pendingMembers.totalItems).toBe(0);
        });

        it('should filter members by full name', () => {
            const { result } = renderHook(() =>
                useMemberPagination(sampleMembers, collectionDetails, true)
            );

            act(() => {
                result.current.setFilterText('Smith');
            });

            expect(result.current.filteredMembersCount).toBe(1);
            expect(result.current.approvedMembers.totalItems).toBe(1);
        });

        it('should clear filter', () => {
            const { result } = renderHook(() =>
                useMemberPagination(sampleMembers, collectionDetails, true)
            );

            act(() => {
                result.current.setFilterText('alice');
            });
            expect(result.current.filteredMembersCount).toBe(1);

            act(() => {
                result.current.clearFilter();
            });
            expect(result.current.filteredMembersCount).toBe(6);
            expect(result.current.filterText).toBe('');
        });
    });

    describe('pagination navigation', () => {
        it('should navigate approved members pages', () => {
            const { result } = renderHook(() =>
                useMemberPagination(sampleMembers, collectionDetails, true)
            );

            // Set page size to 2 to test pagination
            act(() => {
                result.current.onPageSizeChange(2);
            });

            expect(result.current.approvedMembers.currentPage).toBe(1);
            expect(result.current.approvedMembers.totalPages).toBe(2);
            expect(result.current.approvedMembers.data).toHaveLength(2);

            act(() => {
                result.current.approvedMembers.goToNextPage();
            });

            expect(result.current.approvedMembers.currentPage).toBe(2);
            expect(result.current.approvedMembers.data).toHaveLength(2);
        });

        it('should navigate pending members pages independently', () => {
            const { result } = renderHook(() =>
                useMemberPagination(sampleMembers, collectionDetails, true)
            );

            // Set page size to 1 to test pagination
            act(() => {
                result.current.onPageSizeChange(1);
            });

            expect(result.current.pendingMembers.currentPage).toBe(1);
            expect(result.current.pendingMembers.totalPages).toBe(2);

            act(() => {
                result.current.pendingMembers.goToPage(2);
            });

            expect(result.current.pendingMembers.currentPage).toBe(2);
            expect(result.current.approvedMembers.currentPage).toBe(1); // Should not affect approved
        });
    });

    describe('page size changes', () => {
        it('should update page size for both member types', () => {
            const { result } = renderHook(() =>
                useMemberPagination(sampleMembers, collectionDetails, true)
            );

            expect(result.current.currentPageSize).toBe(25); // Default from constants

            act(() => {
                result.current.onPageSizeChange(2);
            });

            expect(result.current.currentPageSize).toBe(2);
            expect(result.current.approvedMembers.totalPages).toBe(2);
            expect(result.current.pendingMembers.totalPages).toBe(1);
            expect(result.current.approvedMembers.currentPage).toBe(1); // Reset to page 1
            expect(result.current.pendingMembers.currentPage).toBe(1); // Reset to page 1
        });
    });

    describe('data changes', () => {
        it('should reset pages when members change', () => {
            const { result, rerender } = renderHook(
                ({ members }) =>
                    useMemberPagination(members, collectionDetails, true),
                { initialProps: { members: sampleMembers } }
            );

            // Set small page size and navigate to page 2
            act(() => {
                result.current.onPageSizeChange(2);
            });

            act(() => {
                result.current.approvedMembers.goToPage(2);
            });
            expect(result.current.approvedMembers.currentPage).toBe(2);

            rerender({ members: sampleMembers.slice(0, 2) });

            expect(result.current.approvedMembers.currentPage).toBe(1);
            expect(result.current.pendingMembers.currentPage).toBe(1);
        });
    });

    describe('sorting', () => {
        it('should sort members by name', () => {
            const { result } = renderHook(() =>
                useMemberPagination(sampleMembers, collectionDetails, true)
            );

            const approvedNames = result.current.approvedMembers.data.map(
                (m) => m.memberName
            );
            expect(approvedNames).toEqual([
                'user.alice',
                'user.bob',
                'user.dave',
                'user.frank',
            ]);

            const pendingNames = result.current.pendingMembers.data.map(
                (m) => m.memberName
            );
            expect(pendingNames).toEqual(['user.carol', 'user.eve']);
        });
    });

    describe('showPagination behavior with minimum page size', () => {
        it('should hide pagination when approved members are less than minimum page size', () => {
            const { result } = renderHook(() =>
                useMemberPagination(sampleMembers, collectionDetails, true)
            );

            // sampleMembers has 4 approved members, which is < 25 (minimum page size)
            expect(result.current.approvedMembers.totalItems).toBe(4);
            expect(result.current.approvedMembers.showPagination).toBe(false);
        });

        it('should hide pagination when pending members are less than minimum page size', () => {
            const { result } = renderHook(() =>
                useMemberPagination(sampleMembers, collectionDetails, true)
            );

            // sampleMembers has 2 pending members, which is < 25 (minimum page size)
            expect(result.current.pendingMembers.totalItems).toBe(2);
            expect(result.current.pendingMembers.showPagination).toBe(false);
        });

        it('should show pagination when members exceed minimum page size', () => {
            // Create 40 approved members (> 25 minimum)
            const manyMembers = Array.from({ length: 40 }, (_, index) => ({
                memberName: `user.member${index + 1}`,
                memberFullName: `Member ${index + 1}`,
                approved: true,
            }));

            const { result } = renderHook(() =>
                useMemberPagination(manyMembers, collectionDetails, true)
            );

            expect(result.current.approvedMembers.totalItems).toBe(40);
            expect(result.current.approvedMembers.showPagination).toBe(true);
        });

        it('should hide pagination when members equal minimum page size', () => {
            // Create exactly 25 approved members (= 25 minimum)
            const exactMinMembers = Array.from({ length: 25 }, (_, index) => ({
                memberName: `user.member${index + 1}`,
                memberFullName: `Member ${index + 1}`,
                approved: true,
            }));

            const { result } = renderHook(() =>
                useMemberPagination(exactMinMembers, collectionDetails, true)
            );

            expect(result.current.approvedMembers.totalItems).toBe(25);
            expect(result.current.approvedMembers.showPagination).toBe(false);
        });

        it('should hide pagination when pagination is disabled regardless of member count', () => {
            // Create 40 approved members but disable pagination
            const manyMembers = Array.from({ length: 40 }, (_, index) => ({
                memberName: `user.member${index + 1}`,
                memberFullName: `Member ${index + 1}`,
                approved: true,
            }));

            const { result } = renderHook(() =>
                useMemberPagination(manyMembers, collectionDetails, false)
            );

            expect(result.current.approvedMembers.totalItems).toBe(40);
            expect(result.current.approvedMembers.showPagination).toBe(false);
            expect(result.current.paginationEnabled).toBe(false);
        });
    });
});
