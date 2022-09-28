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
import { ReactFlowProvider } from 'react-flow-renderer';
import ReactFlowRenderer from '../react-flow/ReactFlowRenderer';
import DependentNode from './DependentNode';
import DomainNode from './DomainNode';
import styled from '@emotion/styled';
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';
import { css, keyframes } from '@emotion/react';

const StyledDiv = styled.div`
    padding: 10px 0 10px 0;
    width: 100%;
    height: 600px;
`;

const TdStyled = styled.td`
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
`;

const LeftMarginSpan = styled.span`
    margin-right: 10px;
    vertical-align: bottom;
`;

const StyleDiv = styled.div`
    width: 100%;
    border-spacing: 0 15px;
    display: table;
    border-collapse: separate;
    border-color: grey;
`;

const StyleTable = styled.table`
    width: 100%;
    border-spacing: 0 15px;
    display: table;
    border-collapse: separate;
    border-color: grey;
`;

const TableHeadStyled = styled.div`
    border-bottom: 2px solid rgb(213, 213, 213);
    color: rgb(154, 154, 154);
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0px 5px 15px;
    word-break: break-all;
    display: flex;
`;

const StyledNameCol = styled.div`
    text-align: ${(props) => props.align};
    width: 28%;
`;

const TDStyledName = styled.div`
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 0;
    vertical-align: middle;
    word-break: break-all;
    width: 28%;
`;

const TDStyledTime = styled.div`
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 0;
    vertical-align: middle;
    word-break: break-all;
    width: 16%;
`;

const StyledTimeCol = styled.div`
    text-align: ${(props) => props.align};
    width: 15%;
`;

const TrStyled = styled.tr`
    box-sizing: border-box;
    margin-top: 10px;
    box-shadow: 0 1px 4px #d9d9d9;
    border: 1px solid #fff;
    -webkit-border-image: none;
    border-image: none;
    -webkit-border-image: initial;
    border-image: initial;
    height: 50px;
`;

const TrTableStyled = styled.div`
    box-sizing: border-box;
    margin-top: 10px;
    box-shadow: 0 1px 4px #d9d9d9;
    border: 1px solid #fff;
    -webkit-border-image: none;
    border-image: none;
    -webkit-border-image: initial;
    border-image: initial;
    display: flex;
    padding: 5px 0 5px 15px;
`;

const nodeTypes = {
    primaryNode: DomainNode,
    inboundNode: DependentNode,
    outboundNode: DependentNode,
};

export default class AuthHistory extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.toggleView = this.toggleView.bind(this);
        this.createElementsList = this.createElementsList.bind(this);
        this.addNodeEdgeElement = this.addNodeEdgeElement.bind(this);
        this.visualizeConnections = this.visualizeConnections.bind(this);
        this.buildTable = this.buildTable.bind(this);
        this.buildReactFlow = this.buildReactFlow.bind(this);
        this.buildExpandButton = this.buildExpandButton.bind(this);
        this.state = {
            expandedIncoming: false,
            expandedOutgoing: false,
        };
    }

    toggleView(direction) {
        if (direction == 'incoming') {
            this.setState({
                expandedIncoming: !this.state.expandedIncoming,
            });
        } else {
            this.setState({
                expandedOutgoing: !this.state.expandedOutgoing,
            });
        }
    }

    addNodeEdgeElement(record, type, index, nodesArr, edgesArr) {
        const position = { x: 0, y: 0 };
        let category,
            edgeSource,
            edgeTarget,
            edgeSourceHandle,
            edgeTargetHandle;

        if (type === 'inbound') {
            category = 'outbound';

            edgeSource = 'inbound-' + index;
            edgeTarget = '0';
            edgeSourceHandle = 'inbound-' + index;
            edgeTargetHandle = 'inbound-handle' + index;
        } else if (type === 'outbound') {
            category = 'inbound';

            edgeSource = '0';
            edgeTarget = 'outbound-' + index;
            edgeSourceHandle = 'outbound-handle' + index;
            edgeTargetHandle = 'outbound-' + index;
        }
        let node = {
            id: type + '-' + index,
            type: type + 'Node',
            data: {
                uriDomain: record['uriDomain'],
                principalDomain: record['principalDomain'],
                principalName: record['principalName'],
                timestamp: record['timestamp'],
                category: category,
                id: type + '-' + index,
            },
            position,
        };

        let edge = {
            id: 'edge-' + type + '-' + index,
            source: edgeSource,
            target: edgeTarget,
            sourceHandle: edgeSourceHandle,
            targetHandle: edgeTargetHandle,
            animated: false,
            type: 'smoothstep',
        };

        nodesArr.push(node);
        edgesArr.push(edge);
    }

    createElementsList(dependencies, type) {
        const position = { x: 0, y: 0 };
        // let newElements = [];
        let nodes = [];
        let edges = [];
        for (let i = 0; i < dependencies.length; i++) {
            let record = dependencies[i];
            this.addNodeEdgeElement(record, type, i, nodes, edges);
        }
        nodes.push({
            id: '0',
            type: 'primaryNode',
            data: {
                data: dependencies,
                domain: this.props.domain,
                category: type,
            },
            position,
        });

        return { nodes, edges };
    }

    visualizeConnections(nodeTypes, dependencies, type) {
        if (dependencies.length < 50) {
            const { nodes, edges } = this.createElementsList(
                dependencies,
                type
            );
            return this.buildReactFlow(nodeTypes, nodes, edges);
        }
        return this.buildTable(dependencies, type);
    }

    buildTable(dependencies, type) {
        let rows = [];
        let left = 'left';
        for (let i = 0; i < dependencies.length; i++) {
            let record = dependencies[i];
            rows.push(
                <TrTableStyled
                    key={
                        'row-' +
                        record.uriDomain +
                        '-' +
                        record.principalDomain +
                        '-' +
                        record.principalName
                    }
                    data-testid='auth-history-row'
                >
                    <TDStyledName align={left}>
                        {record.principalDomain + '.' + record.principalName}
                    </TDStyledName>
                    <TDStyledName align={left}>{record.uriDomain}</TDStyledName>
                    <TDStyledTime align={left}>{record.timestamp}</TDStyledTime>
                </TrTableStyled>
            );
        }
        return (
            <StyleDiv key='auth-history-table' data-testid='authhistorytable'>
                <TableHeadStyled>
                    <StyledNameCol align={left}>Principal</StyledNameCol>
                    <StyledNameCol align={left}>Destination</StyledNameCol>
                    <StyledTimeCol align={left}>Timestamp</StyledTimeCol>
                </TableHeadStyled>
                {rows}
            </StyleDiv>
        );
    }

    buildReactFlow(nodeTypes, nodeList, edgeList) {
        return (
            <StyledDiv>
                <ReactFlowProvider>
                    <ReactFlowRenderer
                        nodeTypes={nodeTypes}
                        nodes={nodeList}
                        edges={edgeList}
                        api={this.api}
                        domain={this.props.domain}
                        _csrf={this.props._csrf}
                    />
                </ReactFlowProvider>
            </StyledDiv>
        );
    }

    buildExpandButton(expandState, direction) {
        const arrowup = 'arrowhead-up-circle-solid';
        const arrowdown = 'arrowhead-down-circle';
        return (
            <LeftMarginSpan>
                <Icon
                    icon={expandState ? arrowup : arrowdown}
                    onClick={() => {
                        this.toggleView(direction);
                    }}
                    color={colors.icons}
                    isLink
                    size={'1.25em'}
                    verticalAlign={'text-bottom'}
                />
            </LeftMarginSpan>
        );
    }

    render() {
        let rows = [];
        let left = 'left';
        rows.push(
            <TrStyled
                key={this.props.domain + '-incoming'}
                data-testid='incoming-row'
            >
                <TdStyled align={left}>
                    {this.buildExpandButton(
                        this.state.expandedIncoming,
                        'incoming'
                    )}
                    {'Incoming'}
                    {this.state.expandedIncoming
                        ? this.visualizeConnections(
                              nodeTypes,
                              this.props.data.incomingDependencies,
                              'inbound'
                          )
                        : []}
                </TdStyled>
            </TrStyled>
        );
        rows.push(
            <TrStyled
                key={this.props.domain + '-outgoing'}
                data-testid='outgoing-row'
            >
                <TdStyled align={left}>
                    {this.buildExpandButton(
                        this.state.expandedOutgoing,
                        'outgoing'
                    )}
                    {'Outgoing'}
                    {this.state.expandedOutgoing
                        ? this.visualizeConnections(
                              nodeTypes,
                              this.props.data.outgoingDependencies,
                              'outbound'
                          )
                        : []}
                </TdStyled>
            </TrStyled>
        );

        return (
            <StyleTable data-testid='auth-history-table'>
                <tbody>{rows}</tbody>
            </StyleTable>
        );
    }
}
