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
import Icon from '../denali/icons/Icon';
import RuleRow from './RuleRow';

const StyleTable = styled.table`
    width: 100%;
    border-spacing: 0;
    display: table;
    border-collapse: separate;
    border-color: grey;
    box-sizing: border-box;
    margin-top: 5px;
    box-shadow: 0 1px 4px #d9d9d9;
    border: 1px solid #fff;
    -webkit-border-image: none;
    border-image: none;
    -webkit-border-image: initial;
    border-image: initial;
    height: 50px;
`;

const TableHeadStyled = styled.th`
    text-align: ${(props) => props.align};
    border-bottom: 2px solid #d5d5d5;
    color: #9a9a9a;
    font-weight: 600;
    font-size: 0.8rem;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0 5px 15px;
    word-break: break-all;
`;

const TableHeadStyledRoleName = styled.th`
    text-align: ${(props) => props.align};
    border-bottom: 2px solid #d5d5d5;
    color: #9a9a9a;
    font-weight: 600;
    font-size: 0.8rem;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0 5px 35px;
    word-break: break-all;
`;

const TableThStyled = styled.th`
    height: 25px;
    margin-left: 10px;
    margin-top: 10px;
    text-align: left;
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
    display: block;
    font-weight: lighter;
`;

const LeftMarginSpan = styled.span`
    margin-right: 10px;
    verticalalign: bottom;
`;

export default class RuleTable extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.state = {
            expanded: true,
        };
    }

    expandRules() {
        this.setState({
            expanded: !this.state.expanded,
        });
    }

    render() {
        const center = 'center';
        const left = 'left';
        const { domain, caption } = this.props;
        const arrowup = 'arrowhead-up-circle-solid';
        const arrowdown = 'arrowhead-down-circle';
        let expandRules = this.expandRules.bind(this);
        let rows = [];
        let length = this.props.data.length;
        let inbound = this.props.category === 'inbound';

        rows = this.props.data.map((item, i) => {
            let color = '';
            if (i % 2 === 0) {
                color = colors.row;
            }
            let key = '';
            if (inbound) {
                key =
                    item.destination_service +
                    item.destination_port +
                    item.identifier;
            } else {
                key = item.source_service + item.source_port + item.identifier;
            }
            return (
                <RuleRow
                    category={this.props.category}
                    domain={domain}
                    details={item}
                    idx={i}
                    color={color}
                    key={key}
                    onUpdateSuccess={this.props.onSubmit}
                    _csrf={this.props._csrf}
                    pageFeatureFlag={this.props.pageFeatureFlag}
                    api={this.api}
                />
            );
        });

        if (!this.state.expanded) {
            return (
                <StyleTable data-testid='segmentation-rule-table'>
                    <thead>
                        <tr>
                            <TableThStyled>
                                <LeftMarginSpan>
                                    <Icon
                                        icon={
                                            this.state.expanded
                                                ? arrowup
                                                : arrowdown
                                        }
                                        onClick={expandRules}
                                        color={colors.icons}
                                        isLink
                                        size={'1.25em'}
                                        verticalAlign={'text-bottom'}
                                    />
                                </LeftMarginSpan>
                                {`${caption} (${length})`}
                            </TableThStyled>
                        </tr>
                    </thead>
                </StyleTable>
            );
        }

        return (
            <StyleTable data-testid='segmentation-rule-table'>
                <thead>
                    <tr>
                        <TableThStyled>
                            <LeftMarginSpan>
                                <Icon
                                    icon={
                                        this.state.expanded
                                            ? arrowup
                                            : arrowdown
                                    }
                                    onClick={expandRules}
                                    color={colors.icons}
                                    isLink
                                    size={'1.25em'}
                                    verticalAlign={'text-bottom'}
                                />
                            </LeftMarginSpan>
                            {`${caption} (${length})`}
                        </TableThStyled>
                    </tr>
                    <tr>
                        <TableHeadStyledRoleName align={left}>
                            Identifier
                        </TableHeadStyledRoleName>
                        <TableHeadStyledRoleName align={left}>
                            {inbound ? 'Destination Service' : 'Source Service'}
                        </TableHeadStyledRoleName>
                        <TableHeadStyled align={left}>
                            {inbound ? 'Destination Port' : 'Source Port'}
                        </TableHeadStyled>

                        <TableHeadStyled align={left}>
                            {inbound ? 'Source Service' : 'Destination Service'}
                        </TableHeadStyled>
                        <TableHeadStyled align={left}>
                            {inbound ? 'Source Port' : 'Destination Port'}
                        </TableHeadStyled>
                        <TableHeadStyled align={left}>Layer</TableHeadStyled>
                        <TableHeadStyled align={left}>Scope</TableHeadStyled>
                        <TableHeadStyled align={center}>
                            Enforcement State
                        </TableHeadStyled>
                        <TableHeadStyled align={center}>Edit</TableHeadStyled>
                        <TableHeadStyled align={center}>Delete</TableHeadStyled>
                    </tr>
                </thead>
                <tbody>{rows}</tbody>
            </StyleTable>
        );
    }
}
