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
import Loader from '../denali/Loader';
import DateUtils from '../utils/DateUtils';
import RequestUtils from '../utils/RequestUtils';

const DetailsDiv = styled.div`
    padding: 10px 15px 15px 45px;
    background-color: ${colors.grey200};
`;

const SectionTitleDiv = styled.div`
    font-weight: 600;
    padding: 10px 0 5px;
`;

const RuleTableStyled = styled.table`
    width: 100%;
    border-spacing: 0;
    border-collapse: collapse;
`;

const RuleTh = styled.th`
    text-align: left;
    border-bottom: 2px solid ${colors.grey500};
    color: ${colors.grey600};
    font-weight: 600;
    font-size: 0.8rem;
    text-transform: uppercase;
    padding: 5px 15px 5px 0;
`;

const RuleTd = styled.td`
    text-align: left;
    vertical-align: top;
    padding: 5px 15px 5px 0;
    border-bottom: 1px solid ${colors.grey400};
    word-break: break-all;
`;

const SmallTextDiv = styled.div`
    font-size: 0.8rem;
    color: ${colors.grey600};
`;

const ErrorDiv = styled.div`
    color: ${colors.red600};
    padding: 5px 0;
`;

const NoteDiv = styled.div`
    color: ${colors.grey700};
    font-style: italic;
`;

// MSD records a peer outside Athenz under the owning service's domain and
// service, with the real target in externalPeer.
export const formatSubject = (subject) => {
    if (!subject) {
        return '';
    }
    if (subject.externalPeer) {
        return subject.externalPeer;
    }
    return `${subject.domainName}.${subject.serviceName}`;
};

export const formatPort = (p) => {
    const range =
        p.endPort === undefined || p.endPort === p.port
            ? `${p.port}`
            : `${p.port}-${p.endPort}`;
    return p.protocol ? `${range}/${p.protocol}` : range;
};

export const formatPorts = (ports) => (ports || []).map(formatPort).join(', ');

export const formatCondition = (condition) => {
    const parts = [condition.enforcementState];
    if (condition.scope && condition.scope.length > 0) {
        parts.push(`scope: ${condition.scope.join(' ')}`);
    }
    if (condition.instances && condition.instances.length > 0) {
        parts.push(`instances: ${condition.instances.join(', ')}`);
    }
    (condition.additionalConditions || []).forEach((c) => {
        parts.push(`${c.key} ${c.operator} ${c.value}`);
    });
    return parts.join('; ');
};

/**
 * Renders one transport policy snapshot: its metadata, the captured ingress
 * and egress rules, and the principals that last recorded using it.
 * Fetches the snapshot and its usage when mounted (one GET each).
 */
export default class SnapshotDetails extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.dateUtils = new DateUtils();
        this.state = {
            snapshot: null,
            usage: null,
            loading: true,
            errorMessage: null,
            usageErrorMessage: null,
        };
    }

    componentDidMount() {
        this.mounted = true;
        const { domain, service, snapshotName } = this.props;
        this.api
            .getSnapshot(domain, service, snapshotName)
            .then((snapshot) => {
                if (this.mounted) {
                    this.setState({ snapshot, loading: false });
                }
            })
            .catch((err) => {
                if (this.mounted) {
                    this.setState({
                        errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                        loading: false,
                    });
                }
            });
        this.api
            .getSnapshotUsage(domain, service, snapshotName)
            .then((usage) => {
                if (this.mounted) {
                    this.setState({ usage });
                }
            })
            .catch((err) => {
                if (this.mounted) {
                    this.setState({
                        usageErrorMessage:
                            RequestUtils.xhrErrorCheckHelper(err),
                    });
                }
            });
    }

    componentWillUnmount() {
        this.mounted = false;
    }

    formatTime(timestamp) {
        return timestamp
            ? this.dateUtils.getLocalDate(timestamp, 'UTC', 'UTC')
            : '-';
    }

    renderRules(rules, ingress) {
        const title = ingress ? 'Inbound' : 'Outbound';
        const testId = ingress
            ? 'snapshot-ingress-table'
            : 'snapshot-egress-table';
        const list = rules || [];
        if (list.length === 0) {
            return (
                <div data-testid={testId}>
                    <SectionTitleDiv>{`${title} (0)`}</SectionTitleDiv>
                    <NoteDiv>
                        No {title.toLowerCase()} rules in this snapshot.
                    </NoteDiv>
                </div>
            );
        }
        const rows = list.map((rule, idx) => {
            const selector = rule.entitySelector || {};
            const match = selector.match || {};
            const peer = ingress ? rule.from : rule.to;
            return (
                <tr key={rule.id || idx} data-testid='snapshot-rule-row'>
                    <RuleTd>
                        {formatSubject(match.athenzService)}
                        <SmallTextDiv>
                            {rule.identifier ? `${rule.identifier} ` : ''}
                            {rule.lastModified
                                ? `modified ${this.formatTime(
                                      rule.lastModified
                                  )}`
                                : ''}
                        </SmallTextDiv>
                    </RuleTd>
                    <RuleTd>{formatPorts(selector.ports)}</RuleTd>
                    <RuleTd>
                        {(match.conditions || []).map((c, i) => (
                            <div key={i}>{formatCondition(c)}</div>
                        ))}
                    </RuleTd>
                    <RuleTd>
                        {(peer && peer.athenzServices
                            ? peer.athenzServices
                            : []
                        ).map((s, i) => (
                            <div key={i}>{formatSubject(s)}</div>
                        ))}
                    </RuleTd>
                    <RuleTd>{formatPorts(peer && peer.ports)}</RuleTd>
                </tr>
            );
        });
        return (
            <div>
                <SectionTitleDiv>{`${title} (${list.length})`}</SectionTitleDiv>
                <RuleTableStyled data-testid={testId}>
                    <thead>
                        <tr>
                            <RuleTh>
                                {ingress
                                    ? 'Destination Service'
                                    : 'Source Service'}
                            </RuleTh>
                            <RuleTh>
                                {ingress ? 'Destination Ports' : 'Source Ports'}
                            </RuleTh>
                            <RuleTh>Conditions</RuleTh>
                            <RuleTh>
                                {ingress
                                    ? 'Source Services'
                                    : 'Destination Services'}
                            </RuleTh>
                            <RuleTh>
                                {ingress ? 'Source Ports' : 'Destination Ports'}
                            </RuleTh>
                        </tr>
                    </thead>
                    <tbody>{rows}</tbody>
                </RuleTableStyled>
            </div>
        );
    }

    renderUsage() {
        const { usage, usageErrorMessage } = this.state;
        let body;
        let count = '';
        if (usageErrorMessage) {
            body = <ErrorDiv>{usageErrorMessage}</ErrorDiv>;
        } else if (!usage) {
            body = <Loader size={'1em'} verticalAlign={'middle'} />;
        } else {
            const principals = usage.principals || [];
            count = ` (${principals.length})`;
            body = (
                <div>
                    {principals.length === 0 && !usage.partial && (
                        <NoteDiv>No recorded use of this snapshot.</NoteDiv>
                    )}
                    {principals.length > 0 && (
                        <RuleTableStyled data-testid='snapshot-usage-table'>
                            <thead>
                                <tr>
                                    <RuleTh>Principal</RuleTh>
                                    <RuleTh>Last used</RuleTh>
                                </tr>
                            </thead>
                            <tbody>
                                {principals.map((p) => (
                                    <tr key={p.name}>
                                        <RuleTd>{p.name}</RuleTd>
                                        <RuleTd>
                                            {this.formatTime(p.time)}
                                        </RuleTd>
                                    </tr>
                                ))}
                            </tbody>
                        </RuleTableStyled>
                    )}
                    {usage.partial && (
                        <NoteDiv>
                            Usage data is incomplete
                            {usage.warning && usage.warning.code
                                ? ` (${usage.warning.code})`
                                : ''}
                            .
                        </NoteDiv>
                    )}
                </div>
            );
        }
        return (
            <div data-testid='snapshot-usage'>
                <SectionTitleDiv>{`Last used by${count}`}</SectionTitleDiv>
                {body}
            </div>
        );
    }

    render() {
        const { snapshot, loading, errorMessage } = this.state;
        if (loading) {
            return (
                <DetailsDiv data-testid='snapshot-details'>
                    <Loader size={'1em'} verticalAlign={'middle'} /> Loading
                    snapshot
                </DetailsDiv>
            );
        }
        if (errorMessage) {
            return (
                <DetailsDiv data-testid='snapshot-details'>
                    <ErrorDiv>{errorMessage}</ErrorDiv>
                </DetailsDiv>
            );
        }
        const rules = snapshot.transportPolicyRules || {};
        return (
            <DetailsDiv data-testid='snapshot-details'>
                {this.renderRules(rules.ingress, true)}
                {this.renderRules(rules.egress, false)}
                {this.renderUsage()}
            </DetailsDiv>
        );
    }
}
