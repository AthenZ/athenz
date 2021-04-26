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
import InstanceRow from './InstanceRow';

const StyleTable = styled.table`
    width: 100%;
    border-spacing: 0 15px;
    display: table;
    border-collapse: separate;
    border-color: grey;
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

const TableHeadStyledGroupName = styled.th`
    text-align: ${(props) => props.align};
    border-bottom: 2px solid #d5d5d5;
    color: #9a9a9a;
    font-weight: 600;
    font-size: 0.8rem;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0 5px 25px;
    word-break: break-all;
`;

export default class InstanceTable extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;

        this.state = {
            instances: props.instances || [],
        };
    }

    componentDidUpdate = (prevProps) => {
        if (prevProps.domain !== this.props.domain) {
            this.setState({
                rows: {},
            });
        } else if (prevProps.instances !== this.props.instances) {
            this.setState({
                instances: this.props.instances || [],
            });
        }
    };

    render() {
        const { domain } = this.props;
        let rows = [];

        if (this.props.instances && this.props.instances.length > 0) {
            rows = this.props.instances.map((item, i) => {
                let color = '';
                return (
                    <InstanceRow
                        details={item}
                        idx={i}
                        domain={domain}
                        color={color}
                        api={this.api}
                        key={item.uuid}
                        onUpdateSuccess={this.props.onSubmit}
                        _csrf={this.props._csrf}
                        category={this.props.category}
                    />
                );
            });
        }

        return (
            <StyleTable key='instance-table' data-testid='instancetable'>
                <colgroup>
                    <col style={{ width: 20 + '%' }} />
                    <col style={{ width: 20 + '%' }} />
                    <col style={{ width: 20 + '%' }} />
                    <col style={{ width: 20 + '%' }} />
                    <col style={{ width: 20 + '%' }} />
                </colgroup>
                {this.props.category === 'dynamic' && (
                    <thead>
                        <tr>
                            <TableHeadStyledGroupName align={'left'}>
                                Instance
                            </TableHeadStyledGroupName>
                            <TableHeadStyledGroupName align={'left'}>
                                Hostname
                            </TableHeadStyledGroupName>
                            <TableHeadStyledGroupName align={'left'}>
                                Provider
                            </TableHeadStyledGroupName>
                            <TableHeadStyledGroupName align={'left'}>
                                Expires On
                            </TableHeadStyledGroupName>
                            <TableHeadStyledGroupName align={'left'}>
                                Last Certificate Refresh
                            </TableHeadStyledGroupName>
                        </tr>
                    </thead>
                )}
                {this.props.category === 'static' && (
                    <thead>
                        <tr>
                            <TableHeadStyledGroupName align={'left'}>
                                Instance
                            </TableHeadStyledGroupName>
                            <TableHeadStyled>Type</TableHeadStyled>
                            <TableHeadStyled>Date Added</TableHeadStyled>
                        </tr>
                    </thead>
                )}
                <tbody>{rows}</tbody>
            </StyleTable>
        );
    }
}
