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
import { render, screen } from '@testing-library/react';
import { ReactFlowProvider } from 'react-flow-renderer';
import DependentNode from '../../../components/visibility/DependentNode';
import DomainNode from '../../../components/visibility/DomainNode';

const inboundDependent = {
    category: 'inbound',
    uriDomain: 'dom1',
    principalDomain: 'dom2',
    principalName: 'svc',
    domain: 'dom1',
    timestamp: '2024-01-01 00:00:00',
};

const inboundDomain = {
    category: 'inbound',
    domain: 'dom1',
    direction: 'left',
    data: [{}, {}],
};

describe('AuthHistory nodes', () => {
    it('DependentNode should re-render only when data changes', () => {
        const { rerender } = render(
            <ReactFlowProvider>
                <DependentNode data={inboundDependent} />
            </ReactFlowProvider>
        );
        expect(screen.getByText('dom2.svc')).toBeInTheDocument();

        // same data (new object, equal contents) should not throw
        rerender(
            <ReactFlowProvider>
                <DependentNode data={{ ...inboundDependent }} />
            </ReactFlowProvider>
        );
        expect(screen.getByText('dom2.svc')).toBeInTheDocument();

        rerender(
            <ReactFlowProvider>
                <DependentNode
                    data={{ ...inboundDependent, principalName: 'svc2' }}
                />
            </ReactFlowProvider>
        );
        expect(screen.getByText('dom2.svc2')).toBeInTheDocument();
    });

    it('DomainNode should re-render only when data changes', () => {
        const { rerender } = render(
            <ReactFlowProvider>
                <DomainNode data={inboundDomain} />
            </ReactFlowProvider>
        );
        expect(screen.getByText('dom1')).toBeInTheDocument();

        rerender(
            <ReactFlowProvider>
                <DomainNode data={{ ...inboundDomain }} />
            </ReactFlowProvider>
        );
        expect(screen.getByText('dom1')).toBeInTheDocument();

        rerender(
            <ReactFlowProvider>
                <DomainNode data={{ ...inboundDomain, domain: 'dom3' }} />
            </ReactFlowProvider>
        );
        expect(screen.getByText('dom3')).toBeInTheDocument();
    });
});
