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
import { fireEvent, waitFor, screen } from '@testing-library/react';
import UserDomains from '../../../components/domain/UserDomains';
import { renderWithRedux } from '../../../tests_utils/ComponentsTestUtils';
import MockApi from '../../../mock/MockApi';

afterEach(() => {
    MockApi.cleanMockApi();
});
describe('UserDomains', () => {
    it('should render', async () => {
        let domains = [];
        domains.push({ name: 'athens' });
        domains.push({ name: 'athens.ci' });

        const { getByTestId } = renderWithRedux(<UserDomains />, {
            domains: { domainsList: domains },
        });

        await waitFor(() =>
            expect(getByTestId('user-domains')).toMatchSnapshot()
        );
    });

    it('should render with no domains', async () => {
        let domains = [];

        const { getByTestId } = renderWithRedux(<UserDomains />, {
            domains: { domainsList: domains },
        });

        await waitFor(() =>
            expect(getByTestId('user-domains')).toMatchSnapshot()
        );
    });

    it('should hide domains on click of arrow', async () => {
        let domains = [];
        domains.push({ name: 'athens' });
        domains.push({ name: 'athens.ci' });
        const { getByTestId } = renderWithRedux(<UserDomains />, {
            domains: { domainsList: domains },
        });
        await waitFor(() => fireEvent.click(getByTestId('toggle-domain')));
        expect(getByTestId('user-domains')).toMatchSnapshot();
    });

    describe('Search functionality', () => {
        let testDomains;

        beforeEach(() => {
            testDomains = [
                { name: 'acme', adminDomain: true },
                { name: 'acme.corp', adminDomain: true },
                { name: 'acme.corp.finance', adminDomain: true },
                { name: 'beta.test', adminDomain: false },
                { name: 'beta.test.staging', adminDomain: false },
                { name: 'gamma', adminDomain: true },
                { name: 'gamma-prod', adminDomain: true },
                { name: 'delta.api', adminDomain: true },
                { name: 'delta.api.v2', adminDomain: false },
                { name: 'epsilon.service', adminDomain: true },
                { name: 'zeta.internal', adminDomain: false },
            ];
        });

        it('should render search input field', async () => {
            const { getByTestId, getByPlaceholderText } = renderWithRedux(
                <UserDomains />,
                {
                    domains: { domainsList: testDomains },
                }
            );

            await waitFor(() => {
                expect(getByTestId('user-domains')).toBeInTheDocument();
                expect(
                    getByPlaceholderText('Search domains')
                ).toBeInTheDocument();
            });
        });

        it('should display all domains when search is empty', async () => {
            const { getByTestId } = renderWithRedux(<UserDomains />, {
                domains: { domainsList: testDomains },
            });

            await waitFor(() => {
                expect(getByTestId('user-domains')).toBeInTheDocument();
                // Check that all domains are visible
                testDomains.forEach((domain) => {
                    expect(screen.getByText(domain.name)).toBeInTheDocument();
                });
            });
        });

        it('should filter domains based on search text', async () => {
            const { getByTestId, getByPlaceholderText } = renderWithRedux(
                <UserDomains />,
                {
                    domains: { domainsList: testDomains },
                }
            );

            const searchInput = getByPlaceholderText('Search domains');

            await waitFor(() => {
                expect(getByTestId('user-domains')).toBeInTheDocument();
            });

            // Search for "acme"
            fireEvent.change(searchInput, { target: { value: 'acme' } });

            await waitFor(() => {
                // Should show acme domains
                expect(screen.getByText('acme')).toBeInTheDocument();
                expect(screen.getByText('acme.corp')).toBeInTheDocument();
                expect(
                    screen.getByText('acme.corp.finance')
                ).toBeInTheDocument();

                // Should not show non-acme domains
                expect(screen.queryByText('beta.test')).not.toBeInTheDocument();
                expect(screen.queryByText('gamma')).not.toBeInTheDocument();
            });
        });

        it('should show no domains when search matches nothing', async () => {
            const { getByTestId, getByPlaceholderText } = renderWithRedux(
                <UserDomains />,
                {
                    domains: { domainsList: testDomains },
                }
            );

            const searchInput = getByPlaceholderText('Search domains');

            await waitFor(() => {
                expect(getByTestId('user-domains')).toBeInTheDocument();
            });

            // Search for something that doesn't exist
            fireEvent.change(searchInput, { target: { value: 'nonexistent' } });

            await waitFor(() => {
                // Should not show any domains
                testDomains.forEach((domain) => {
                    expect(
                        screen.queryByText(domain.name)
                    ).not.toBeInTheDocument();
                });
            });
        });

        it('should prioritize exact matches in search results', async () => {
            const { getByTestId, getByPlaceholderText } = renderWithRedux(
                <UserDomains />,
                {
                    domains: { domainsList: testDomains },
                }
            );

            const searchInput = getByPlaceholderText('Search domains');

            await waitFor(() => {
                expect(getByTestId('user-domains')).toBeInTheDocument();
            });

            // Search for exact match "acme"
            fireEvent.change(searchInput, { target: { value: 'acme' } });

            await waitFor(() => {
                const domainLinks = screen.getAllByRole('link');
                const domainNames = domainLinks.map((link) => link.textContent);

                // "acme" should appear before "acme.corp" and "acme.corp.finance"
                const acmeIndex = domainNames.indexOf('acme');
                const acmeCorpIndex = domainNames.indexOf('acme.corp');

                expect(acmeIndex).toBeLessThan(acmeCorpIndex);
            });
        });

        it('should prioritize domains starting with search term', async () => {
            const { getByTestId, getByPlaceholderText } = renderWithRedux(
                <UserDomains />,
                {
                    domains: { domainsList: testDomains },
                }
            );

            const searchInput = getByPlaceholderText('Search domains');

            await waitFor(() => {
                expect(getByTestId('user-domains')).toBeInTheDocument();
            });

            // Search for "beta"
            fireEvent.change(searchInput, { target: { value: 'beta' } });

            await waitFor(() => {
                const domainLinks = screen.getAllByRole('link');
                const domainNames = domainLinks.map((link) => link.textContent);

                // "beta.test" should appear before "beta.test.staging"
                const betaTestIndex = domainNames.indexOf('beta.test');
                const betaTestStagingIndex =
                    domainNames.indexOf('beta.test.staging');

                expect(betaTestIndex).toBeLessThan(betaTestStagingIndex);
            });
        });

        it('should clear search and show all domains when search text is removed', async () => {
            const { getByTestId, getByPlaceholderText } = renderWithRedux(
                <UserDomains />,
                {
                    domains: { domainsList: testDomains },
                }
            );

            const searchInput = getByPlaceholderText('Search domains');

            await waitFor(() => {
                expect(getByTestId('user-domains')).toBeInTheDocument();
            });

            // First search for something
            fireEvent.change(searchInput, { target: { value: 'acme' } });

            await waitFor(() => {
                expect(screen.getByText('acme')).toBeInTheDocument();
                expect(screen.queryByText('beta.test')).not.toBeInTheDocument();
            });

            // Clear the search
            fireEvent.change(searchInput, { target: { value: '' } });

            await waitFor(() => {
                // Should show all domains again
                testDomains.forEach((domain) => {
                    expect(screen.getByText(domain.name)).toBeInTheDocument();
                });
            });
        });

        it('should handle case-insensitive search', async () => {
            const { getByTestId, getByPlaceholderText } = renderWithRedux(
                <UserDomains />,
                {
                    domains: { domainsList: testDomains },
                }
            );

            const searchInput = getByPlaceholderText('Search domains');

            await waitFor(() => {
                expect(getByTestId('user-domains')).toBeInTheDocument();
            });

            // Search with uppercase
            fireEvent.change(searchInput, { target: { value: 'ACME' } });

            await waitFor(() => {
                expect(screen.getByText('acme')).toBeInTheDocument();
                expect(screen.getByText('acme.corp')).toBeInTheDocument();
            });
        });

        it('should handle search with whitespace', async () => {
            const { getByTestId, getByPlaceholderText } = renderWithRedux(
                <UserDomains />,
                {
                    domains: { domainsList: testDomains },
                }
            );

            const searchInput = getByPlaceholderText('Search domains');

            await waitFor(() => {
                expect(getByTestId('user-domains')).toBeInTheDocument();
            });

            // Search with leading/trailing whitespace
            fireEvent.change(searchInput, { target: { value: '  acme  ' } });

            await waitFor(() => {
                expect(screen.getByText('acme')).toBeInTheDocument();
                expect(screen.getByText('acme.corp')).toBeInTheDocument();
            });
        });
    });
});
