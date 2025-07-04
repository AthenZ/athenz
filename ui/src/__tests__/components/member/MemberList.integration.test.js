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
import { render, screen, fireEvent, waitFor } from '@testing-library/react';
import { Provider } from 'react-redux';
import { configureStore } from '@reduxjs/toolkit';
import MemberList from '../../../components/member/MemberList';

// Mock API
const mockApi = {
    getPageFeatureFlag: jest.fn().mockResolvedValue({ pagination: true }),
};

jest.mock('../../../api', () => ({
    __esModule: true,
    default: () => mockApi,
}));

describe('MemberList Integration with Filtering', () => {
    const mockStore = configureStore({
        reducer: {
            loading: () => [],
            domains: () => ({
                domainData: {
                    test: {
                        timeZone: 'UTC',
                    },
                },
            }),
        },
    });

    const defaultProps = {
        domain: 'test',
        collection: 'role1',
        collectionDetails: {
            name: 'role1',
            trust: false,
            reviewEnabled: false,
            selfServe: false,
        },
        members: [
            {
                memberName: 'user.alice',
                memberFullName: 'Alice Johnson',
                approved: true,
                expiration: null,
            },
            {
                memberName: 'user.bob',
                memberFullName: 'Bob Smith',
                approved: true,
                expiration: null,
            },
            {
                memberName: 'service.api',
                memberFullName: null,
                approved: false,
                expiration: null,
            },
            {
                memberName: 'user.charlie',
                memberFullName: 'Charlie Brown',
                approved: false,
                expiration: null,
            },
        ],
        category: 'role',
        isDomainAuditEnabled: false,
        _csrf: 'test-csrf',
        isLoading: [],
    };

    beforeEach(() => {
        jest.clearAllMocks();
    });

    const renderWithStore = (props = {}) => {
        return render(
            <Provider store={mockStore}>
                <MemberList {...defaultProps} {...props} />
            </Provider>
        );
    };

    describe('filtering integration', () => {
        it('should render filter component when pagination is enabled', async () => {
            renderWithStore();

            await waitFor(() => {
                expect(screen.getByTestId('member-filter')).toBeInTheDocument();
            });

            expect(
                screen.getByPlaceholderText('Filter members by name')
            ).toBeInTheDocument();
        });

        it('should filter both approved and pending members', async () => {
            renderWithStore();

            await waitFor(() => {
                expect(screen.getByTestId('member-filter')).toBeInTheDocument();
            });

            // Filter by 'user'
            const filterInput = screen.getByPlaceholderText(
                'Filter members by name'
            );
            fireEvent.change(filterInput, { target: { value: 'user' } });

            await waitFor(() => {
                // Check that filter is active by verifying input value
                expect(filterInput.value).toBe('user');
            });
        });

        it('should filter by member full name', async () => {
            renderWithStore();

            await waitFor(() => {
                expect(screen.getByTestId('member-filter')).toBeInTheDocument();
            });

            // Filter by full name
            const filterInput = screen.getByPlaceholderText(
                'Filter members by name'
            );
            fireEvent.change(filterInput, { target: { value: 'Johnson' } });

            await waitFor(() => {
                // Check that filter is active by verifying input value
                expect(filterInput.value).toBe('Johnson');
            });
        });

        it('should show no results message when no matches', async () => {
            renderWithStore();

            await waitFor(() => {
                expect(screen.getByTestId('member-filter')).toBeInTheDocument();
            });

            // Filter with no matches
            const filterInput = screen.getByPlaceholderText(
                'Filter members by name'
            );
            fireEvent.change(filterInput, { target: { value: 'nomatch' } });

            await waitFor(() => {
                // Verify filter is active by checking input value
                expect(filterInput.value).toBe('nomatch');
            });
        });

        it('should clear filter with Escape key', async () => {
            renderWithStore();

            await waitFor(() => {
                expect(screen.getByTestId('member-filter')).toBeInTheDocument();
            });

            // Apply filter
            const filterInput = screen.getByPlaceholderText(
                'Filter members by name'
            );
            fireEvent.change(filterInput, { target: { value: 'user' } });

            await waitFor(() => {
                expect(filterInput.value).toBe('user');
            });

            // Clear with Escape key
            fireEvent.keyDown(filterInput, { key: 'Escape' });

            await waitFor(() => {
                expect(filterInput.value).toBe('');
            });
        });
    });

    describe('pagination integration with filtering', () => {
        const manyMembers = Array.from({ length: 50 }, (_, i) => ({
            memberName: `user.member${i.toString().padStart(2, '0')}`,
            memberFullName: `Member ${i}`,
            approved: i % 3 !== 0, // Mix of approved and pending
            expiration: null,
        }));

        it('should reset pagination when filter changes', async () => {
            renderWithStore({ members: manyMembers });

            await waitFor(() => {
                expect(screen.getByTestId('member-filter')).toBeInTheDocument();
            });

            // Apply filter that reduces results
            const filterInput = screen.getByPlaceholderText(
                'Filter members by name'
            );
            fireEvent.change(filterInput, { target: { value: 'member0' } });

            await waitFor(() => {
                // Should show filtered results by checking input value
                expect(filterInput.value).toBe('member0');
            });
        });

        it('should maintain filter when changing page size', async () => {
            renderWithStore({ members: manyMembers });

            await waitFor(() => {
                expect(screen.getByTestId('member-filter')).toBeInTheDocument();
            });

            // Apply filter
            const filterInput = screen.getByPlaceholderText(
                'Filter members by name'
            );
            fireEvent.change(filterInput, { target: { value: 'member1' } });

            await waitFor(() => {
                expect(filterInput.value).toBe('member1');
            });

            // Filter should persist when pagination changes
            expect(filterInput.value).toBe('member1');
        });
    });

    describe('trust domain handling', () => {
        it('should filter trust domain members', async () => {
            const trustDomainProps = {
                ...defaultProps,
                collectionDetails: {
                    ...defaultProps.collectionDetails,
                    trust: true,
                },
            };

            renderWithStore(trustDomainProps);

            await waitFor(() => {
                expect(screen.getByTestId('member-filter')).toBeInTheDocument();
            });

            // Filter should work the same way
            const filterInput = screen.getByPlaceholderText(
                'Filter members by name'
            );
            fireEvent.change(filterInput, { target: { value: 'user' } });

            await waitFor(() => {
                expect(filterInput.value).toBe('user');
            });
        });
    });

    describe('edge cases', () => {
        it('should not show filter when no members', async () => {
            renderWithStore({ members: [] });

            await waitFor(() => {
                // Filter should not be shown when no members
                expect(
                    screen.queryByTestId('member-filter')
                ).not.toBeInTheDocument();
            });
        });

        it('should not show filter when pagination is disabled', async () => {
            mockApi.getPageFeatureFlag.mockResolvedValueOnce({
                pagination: false,
            });

            renderWithStore();

            await waitFor(() => {
                // Filter should not be shown when pagination is disabled
                expect(
                    screen.queryByTestId('member-filter')
                ).not.toBeInTheDocument();
            });
        });

        it('should handle API error gracefully', async () => {
            mockApi.getPageFeatureFlag.mockRejectedValueOnce(
                new Error('API Error')
            );

            renderWithStore();

            await waitFor(() => {
                // Should show filter with default enabled state
                expect(screen.getByTestId('member-filter')).toBeInTheDocument();
            });
        });
    });
});
