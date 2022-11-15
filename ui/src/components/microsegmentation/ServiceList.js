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
import Menu from '../denali/Menu/Menu';

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
    color: blue;
`;

const StyledLink = styled.a`
    cursor: pointer;
`;

const StyledInvalidLink = styled.a``;

const StyledMessageDiv = styled.div`
    min-width: 200px;
`;

const StyledMenu = styled(Menu)`
    min-width: 200px;
`;

class ServiceList extends React.Component {
    constructor(props) {
        super(props);
        this.localDate = new DateUtils();
        this.viewServiceDetails = this.viewServiceDetails.bind(this);
    }

    viewServiceDetails(item) {
        let index = item.lastIndexOf('.');
        let dom = item.substring(0, index);
        let service = item.substring(index + 1);
        this.props.router.push(
            `/domain/${dom}/service/${service}/instance/dynamic`,
            `/domain/${dom}/service/${service}/instance/dynamic`
        );
    }

    render() {
        const { list } = this.props;
        let rows;
        rows = list.map((item, i) => {
            return (
                <StyledTr key={item + i + new Date().getTime()}>
                    <StyledTd>
                        {!item.includes('*') && (
                            <StyledLink
                                onClick={() => {
                                    this.viewServiceDetails(item);
                                }}
                            >
                                {' '}
                                {item}{' '}
                            </StyledLink>
                        )}

                        {item.includes('*') && <p>{item} </p>}
                    </StyledTd>
                </StyledTr>
            );
        });

        return (
            <StyledDiv
                key={'service-list'}
                data-testid={'segmentation-service-list'}
            >
                <StyleTable>
                    <thead>
                        <StyledTr>
                            <StyledTh> Services </StyledTh>
                        </StyledTr>
                    </thead>
                    <tbody>{rows}</tbody>
                </StyleTable>
            </StyledDiv>
        );
    }
}
export default withRouter(ServiceList);
