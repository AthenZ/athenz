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
import DateUtils from '../utils/DateUtils';
import { withRouter } from 'next/router';
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';
import Menu from '../denali/Menu/Menu';
import DeleteModal from '../modal/DeleteModal';
import RequestUtils from '../utils/RequestUtils';

const StyleTable = styled.table`
    width: 100%;
    text-align: center;
    border-spacing: 0;
    display: table;
    border-collapse: separate;
    border-color: black;
    box-sizing: border-box;
    margin-top: 5px;
    box-shadow: 0 1px 4px #d9d9d9;
    border: 5px solid #fff;
    -webkit-border-image: none;
    border-image: none;
    -webkit-border-image: initial;
    border-image: initial;
    max-height: 600px;
`;

const StyledDiv = styled.div`
    display: inline-block;
    overflow-y: scroll;
    max-height: 600px;
    max-width: 600px;
`;

const StyledTr = styled.tr`
    &:nth-child(even) {
        background-color: #3570f40d;
    }
`;

const StyledTh = styled.th`
    padding: 6px;
    border: 1px solid #dddddd;
`;

const StyledTd = styled.td`
    border: 1px solid #dddddd;
    padding: 5px;
    white-space: pre;
`;

const MenuDiv = styled.div`
    padding: 5px 10px;
    background-color: black;
    color: white;
    font-size: 12px;
`;

class EnforcementStateList extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
        this.localDate = new DateUtils();
    }

    onClickDelete(assertionId, conditionId, policyName) {
        if (this.props.list.length > 1) {
            this.props.deleteCondition(assertionId, conditionId, policyName);
        }
    }

    render() {
        const { list } = this.props;
        let rows = '';
        rows =
            list &&
            list.map((item, i) => {
                let policyName = item['policyName'].split(':policy.');
                let clickDelete = this.onClickDelete.bind(
                    this,
                    item['assertionId'],
                    item['id'],
                    policyName[1]
                );
                return (
                    <StyledTr key={item + i + new Date().getTime()}>
                        <StyledTd>{item['enforcementstate']}</StyledTd>
                        <StyledTd>
                            {item['instances'].replace(/,/g, '\n')}
                        </StyledTd>
                        <StyledTd>
                            <Menu
                                placement='bottom-start'
                                trigger={
                                    <span>
                                        <Icon
                                            icon={'trash'}
                                            onClick={clickDelete}
                                            color={
                                                list && list.length > 1
                                                    ? colors.icons
                                                    : colors.grey500
                                            }
                                            isLink
                                            size={'1.25em'}
                                            verticalAlign={'text-bottom'}
                                        />
                                    </span>
                                }
                            >
                                <MenuDiv>Delete Enforcement Condition</MenuDiv>
                            </Menu>
                        </StyledTd>
                    </StyledTr>
                );
            });

        return (
            <StyledDiv
                key={'enforcement-state-list'}
                data-testid={'microsegmentation-enforcement-list'}
            >
                <StyleTable>
                    <StyledTr>
                        <StyledTh> Enforcement State </StyledTh>
                        <StyledTh> Hosts </StyledTh>
                        <StyledTh> Action </StyledTh>
                    </StyledTr>
                    {rows}
                </StyleTable>
            </StyledDiv>
        );
    }
}
export default withRouter(EnforcementStateList);
