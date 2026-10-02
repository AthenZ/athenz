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
import { render, screen, waitFor } from '@testing-library/react';
import SnapshotDetails, {
    formatCondition,
    formatPort,
    formatPorts,
    formatSubject,
} from '../../../components/microsegmentation/SnapshotDetails';

const domain = 'dom';
const service = 'svc';

const snapshot = {
    domainName: domain,
    serviceName: service,
    name: 'v1',
    createdTime: '2026-09-16T10:00:00.000Z',
    modified: '2026-09-20T12:30:00.000Z',
    active: true,
    transportPolicyRules: {
        ingress: [
            {
                id: 34567,
                identifier: 'api-in',
                lastModified: '2026-09-10T09:00:00.000Z',
                entitySelector: {
                    match: {
                        athenzService: {
                            domainName: domain,
                            serviceName: service,
                        },
                        conditions: [
                            {
                                enforcementState: 'ENFORCE',
                                scope: ['ONPREM', 'AWS'],
                                instances: ['host1', 'host2'],
                            },
                        ],
                    },
                    ports: [{ port: 4443, endPort: 4443, protocol: 'TCP' }],
                },
                from: {
                    athenzServices: [
                        { domainName: 'peer', serviceName: 'client' },
                    ],
                    ports: [{ port: 1024, endPort: 65535, protocol: 'TCP' }],
                },
            },
        ],
        egress: [
            {
                id: 76543,
                lastModified: '2026-09-11T09:00:00.000Z',
                entitySelector: {
                    match: {
                        athenzService: {
                            domainName: domain,
                            serviceName: service,
                        },
                        conditions: [
                            {
                                enforcementState: 'REPORT',
                                additionalConditions: [
                                    {
                                        key: 'env',
                                        operator: 'EQUALS',
                                        value: 'prod',
                                    },
                                ],
                            },
                        ],
                    },
                    ports: [{ port: 1024, endPort: 65535, protocol: 'TCP' }],
                },
                to: {
                    athenzServices: [
                        { domainName: 'peer', serviceName: 'db' },
                        {
                            domainName: domain,
                            serviceName: service,
                            externalPeer: 'db.example.com/32',
                        },
                    ],
                    ports: [{ port: 3306, endPort: 3306, protocol: 'TCP' }],
                },
            },
        ],
    },
};

const renderDetails = (api) =>
    render(
        <SnapshotDetails
            api={api}
            domain={domain}
            service={service}
            snapshotName={'v1'}
        />
    );

describe('SnapshotDetails formatting helpers', () => {
    it('formats subjects, ports and conditions', () => {
        expect(formatSubject({ domainName: 'a.b', serviceName: 'c' })).toBe(
            'a.b.c'
        );
        expect(formatSubject(undefined)).toBe('');
        expect(
            formatSubject({
                domainName: 'a.b',
                serviceName: 'c',
                externalPeer: 'x.example.com/32',
            })
        ).toBe('x.example.com/32');
        expect(formatPort({ port: 443, endPort: 443, protocol: 'TCP' })).toBe(
            '443/TCP'
        );
        expect(
            formatPort({ port: 1024, endPort: 65535, protocol: 'UDP' })
        ).toBe('1024-65535/UDP');
        expect(formatPort({ port: 80 })).toBe('80');
        expect(
            formatPorts([
                { port: 1, endPort: 1, protocol: 'TCP' },
                { port: 2, endPort: 3, protocol: 'TCP' },
            ])
        ).toBe('1/TCP, 2-3/TCP');
        expect(formatPorts(undefined)).toBe('');
        expect(
            formatCondition({
                enforcementState: 'ENFORCE',
                scope: ['ONPREM'],
                instances: ['h1'],
            })
        ).toBe('ENFORCE; scope: ONPREM; instances: h1');
        expect(formatCondition({ enforcementState: 'REPORT' })).toBe('REPORT');
        expect(
            formatCondition({
                enforcementState: 'ENFORCE',
                additionalConditions: [
                    { key: 'env', operator: 'EQUALS', value: 'prod' },
                    { key: 'tier', operator: 'IN', value: 'a,b' },
                ],
            })
        ).toBe('ENFORCE; env EQUALS prod; tier IN a,b');
    });
});

describe('SnapshotDetails', () => {
    it('renders metadata, ingress and egress rules and usage', async () => {
        const api = {
            getSnapshot: jest.fn().mockResolvedValue(snapshot),
            getSnapshotUsage: jest.fn().mockResolvedValue({
                principals: [
                    {
                        name: 'peer.controller',
                        time: '2026-09-28T07:00:00.000Z',
                    },
                ],
                partial: false,
            }),
        };
        const { getByTestId } = renderDetails(api);

        await waitFor(() =>
            expect(getByTestId('snapshot-ingress-table')).toBeInTheDocument()
        );
        expect(api.getSnapshot).toHaveBeenCalledWith(domain, service, 'v1');
        expect(screen.getByText('Inbound (1)')).toBeInTheDocument();
        expect(screen.getByText('Outbound (1)')).toBeInTheDocument();
        expect(
            screen.getByText(
                'ENFORCE; scope: ONPREM AWS; instances: host1, host2'
            )
        ).toBeInTheDocument();
        // ingress source ports and egress source ports share this range
        expect(screen.getAllByText('1024-65535/TCP')).toHaveLength(2);
        expect(screen.getByText('REPORT; env EQUALS prod')).toBeInTheDocument();
        expect(screen.getByText('peer.client')).toBeInTheDocument();
        expect(screen.getByText('peer.db')).toBeInTheDocument();
        // an external peer shows its own target, not the owning service
        expect(screen.getByText('db.example.com/32')).toBeInTheDocument();
        expect(screen.getAllByText(`${domain}.${service}`)).toHaveLength(2);
        expect(screen.getByText('3306/TCP')).toBeInTheDocument();
        // snapshot metadata lives in the list row, not repeated here
        expect(screen.queryByText(/^Created /)).toBeNull();
        // internal assertion ids are not shown; the rule's modified time is
        expect(screen.queryByText(/\bid \d+/)).toBeNull();

        await waitFor(() =>
            expect(screen.getByText('peer.controller')).toBeInTheDocument()
        );
        expect(screen.getByText('Last used by (1)')).toBeInTheDocument();
        expect(getByTestId('snapshot-usage-table')).toBeInTheDocument();
        expect(screen.getByText('Principal')).toBeInTheDocument();
        expect(screen.getByText('Last used')).toBeInTheDocument();
        expect(screen.getByText('2026-09-28 07:00 UTC')).toBeInTheDocument();
        expect(getByTestId('snapshot-details')).toMatchSnapshot();
    });

    it('reports incomplete usage and empty rule sets', async () => {
        const api = {
            getSnapshot: jest.fn().mockResolvedValue({
                ...snapshot,
                modified: undefined,
                active: false,
                transportPolicyRules: { ingress: [], egress: [] },
            }),
            getSnapshotUsage: jest.fn().mockResolvedValue({
                principals: [],
                partial: true,
                warning: {
                    source: 'usage-store',
                    code: 'UPSTREAM_UNAVAILABLE',
                },
            }),
        };
        renderDetails(api);

        await waitFor(() =>
            expect(screen.getByText('Inbound (0)')).toBeInTheDocument()
        );
        expect(
            screen.getByText('No inbound rules in this snapshot.')
        ).toBeInTheDocument();
        expect(screen.queryByText(/^Created /)).toBeNull();
        await waitFor(() =>
            expect(
                screen.getByText(
                    'Usage data is incomplete (UPSTREAM_UNAVAILABLE).'
                )
            ).toBeInTheDocument()
        );
        expect(
            screen.queryByText('No recorded use of this snapshot.')
        ).toBeNull();
    });

    it('states when a snapshot has no recorded use', async () => {
        const api = {
            getSnapshot: jest.fn().mockResolvedValue(snapshot),
            getSnapshotUsage: jest
                .fn()
                .mockResolvedValue({ principals: [], partial: false }),
        };
        renderDetails(api);

        await waitFor(() =>
            expect(
                screen.getByText('No recorded use of this snapshot.')
            ).toBeInTheDocument()
        );
    });

    it('shows errors from the snapshot and usage calls', async () => {
        const notFound = new Error('nf');
        notFound.statusCode = 404;
        notFound.body = { message: 'MSD: snapshot not found' };
        const api = {
            getSnapshot: jest.fn().mockRejectedValue(notFound),
            getSnapshotUsage: jest.fn().mockRejectedValue(notFound),
        };
        renderDetails(api);

        await waitFor(() =>
            expect(
                screen.getByText(
                    'Status: 404. Message: MSD: snapshot not found'
                )
            ).toBeInTheDocument()
        );
        expect(screen.queryByTestId('snapshot-ingress-table')).toBeNull();
    });
});
