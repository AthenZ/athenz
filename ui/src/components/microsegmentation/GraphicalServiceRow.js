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
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';
import styled from '@emotion/styled';
import { css, keyframes } from '@emotion/react';
import ReactFlowRenderer from '../react-flow/ReactFlowRenderer';
import { ReactFlowProvider } from 'react-flow-renderer';
import CustomPrimaryServiceNode from './CustomPrimaryServiceNode';
import CustomSecondaryServiceNode from './CustomSecondaryServiceNode';

const TdStyled = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
`;

const colorTransition = keyframes`
        0% {
            background-color: rgba(21, 192, 70, 0.20);
        }
        100% {
            background-color: transparent;
        }
`;

const TrStyled = styled.tr`
    ${(props) =>
        props.isSuccess &&
        css`
            animation: ${colorTransition} 3s ease;
        `}
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

const TrStyledExpanded = styled.tr`
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

const LeftMarginSpan = styled.span`
    margin-right: 10px;
    vertical-align: bottom;
`;

const StyledDiv = styled.div`
    padding: 10px 0 10px 0;
    width: 100%;
    height: 600px;
`;

const nodeTypes = {
    primaryNode: CustomPrimaryServiceNode,
    inboundNode: CustomSecondaryServiceNode,
    outboundNode: CustomSecondaryServiceNode,
};

export default class GraphicalServiceRow extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.toggleView = this.toggleView.bind(this);
        this.createElementsList = this.createElementsList.bind(this);
        this.addNodeEdgeElement = this.addNodeEdgeElement.bind(this);
        this.state = {
            name: this.props.name,
            errorMessage: null,
            expandedView: false,
        };
    }

    toggleView() {
        this.setState({
            expandedView: !this.state.expandedView,
        });
    }

    addNodeEdgeElement(policyRule, type, index, nodesArr, edgesArr) {
        const position = { x: 0, y: 0 };
        let nodeDataName,
            nodeDataSourcePort,
            category,
            edgeSource,
            edgeTarget,
            edgeSourceHandle,
            edgeTargetHandle;

        if (type === 'inbound') {
            nodeDataName = policyRule['source_services'][index];
            nodeDataSourcePort = policyRule['source_port'];
            category = 'outbound';

            edgeSource = policyRule['assertionIdx'] + '-' + index;
            edgeTarget = '0';
            edgeSourceHandle = type;
            edgeTargetHandle = policyRule['assertionIdx'] + '_' + type;
        } else if (type === 'outbound') {
            nodeDataName = policyRule['destination_services'][index];
            nodeDataSourcePort = policyRule['destination_port'];
            category = 'inbound';

            edgeSource = '0';
            edgeTarget = policyRule['assertionIdx'] + '-' + index;
            edgeSourceHandle = policyRule['assertionIdx'] + '_' + type;
            edgeTargetHandle = type;
        }
        let node = {
            id: policyRule['assertionIdx'] + '-' + index,
            type: type + 'Node',
            data: {
                name: nodeDataName,
                assertionIdx: policyRule['assertionIdx'],
                source_port: nodeDataSourcePort,
                category: category,
                id: policyRule['assertionIdx'] + '-' + index,
            },
            position,
        };

        let edge = {
            id: 'edge-' + policyRule['assertionIdx'] + '-' + index,
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

    createElementsList() {
        const position = { x: 0, y: 0 };
        let newNodes = [];
        let newEdges = [];
        newNodes.push({
            id: '0',
            type: 'primaryNode',
            data: {
                data: this.props.data,
                name: this.state.name,
                domain: this.props.domain,
                api: this.api,
                _csrf: this.props._csrf,
                onSubmit: this.props.onDeleteCondition,
            },
            position,
        });
        for (let i = 0; i < this.props.data.length; i++) {
            let rule = this.props.data[i];
            if (rule['category'] == 'inbound') {
                for (let j = 0; j < rule['source_services'].length; j++) {
                    this.addNodeEdgeElement(
                        rule,
                        'inbound',
                        j,
                        newNodes,
                        newEdges
                    );
                }
            } else if (rule['category'] == 'outbound') {
                for (let j = 0; j < rule['destination_services'].length; j++) {
                    this.addNodeEdgeElement(
                        rule,
                        'outbound',
                        j,
                        newNodes,
                        newEdges
                    );
                }
            }
        }

        return { nodesList: newNodes, edgesList: newEdges };
    }

    render() {
        const { nodesList, edgesList } = this.createElementsList();
        let rows = [];
        let left = 'left';
        const arrowup = 'arrowhead-up-circle-solid';
        const arrowdown = 'arrowhead-down-circle';
        if (this.state.expandedView) {
            rows.push(
                <TrStyledExpanded
                    key={this.state.name}
                    data-testid='policy-row'
                >
                    <TdStyled align={left}>
                        <div>
                            <LeftMarginSpan>
                                <Icon
                                    icon={
                                        this.state.expandedView
                                            ? arrowup
                                            : arrowdown
                                    }
                                    onClick={this.toggleView}
                                    color={colors.icons}
                                    isLink
                                    size={'1.25em'}
                                    verticalAlign={'text-bottom'}
                                />
                            </LeftMarginSpan>
                            {this.state.name}
                        </div>
                        <StyledDiv>
                            <ReactFlowProvider>
                                <ReactFlowRenderer
                                    nodeTypes={nodeTypes}
                                    nodes={nodesList}
                                    edges={edgesList}
                                    name={this.state.name}
                                    api={this.api}
                                    domain={this.props.domain}
                                    _csrf={this.props._csrf}
                                    onDeleteCondition={
                                        this.props.onDeleteCondition
                                    }
                                />
                            </ReactFlowProvider>
                        </StyledDiv>
                    </TdStyled>
                </TrStyledExpanded>
            );
        } else {
            rows.push(
                <TrStyled key={this.state.name} data-testid='role-policy-row'>
                    <TdStyled align={left}>
                        <LeftMarginSpan>
                            <Icon
                                icon={
                                    this.state.expandedView
                                        ? arrowup
                                        : arrowdown
                                }
                                color={colors.icons}
                                onClick={this.toggleView}
                                isLink
                                size={'1.25em'}
                                verticalAlign={'text-bottom'}
                            />
                        </LeftMarginSpan>
                        {this.state.name}
                    </TdStyled>
                </TrStyled>
            );
        }

        return rows;
    }
}
