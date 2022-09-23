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

const TemplateDesc = styled.table`
    display: table;
    border-collapse: separate;
    border-spacing: 2px;
    border-color: ${colors.grey600};
`;

const TdStyled = styled.td`
    padding: 20px;
    text-align: left;
    vertical-align: middle;
    word-break: break-all;
    font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    display: table-cell;
    background-color: ${(props) => props.color};
`;

const TrStyled = styled.tr`
    background-color: ${(props) => props.color};
`;

export default class TemplateDescription extends React.Component {
    render() {
        return (
            <TdStyled
                colSpan={7}
                color={this.props.color}
                data-testid='provider-table'
            >
                <TemplateDesc>
                    <thead>
                        <TrStyled>
                            <TdStyled>{this.props.description}</TdStyled>
                        </TrStyled>
                    </thead>
                </TemplateDesc>
            </TdStyled>
        );
    }
}
