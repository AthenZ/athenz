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
import Button from '../denali/Button';
import { colors } from '../denali/styles';
import { countLabel, splitByType } from './selfServiceUtils';

const Bar = styled.div`
    align-items: center;
    background: ${colors.white};
    border-top: 1px solid ${colors.grey400};
    bottom: 0;
    box-shadow: 0 -2px 8px rgba(0, 0, 0, 0.08);
    display: flex;
    justify-content: space-between;
    left: 0;
    padding: 12px 30px;
    position: sticky;
    z-index: 3;
`;

const Count = styled.div`
    color: ${colors.grey800};
    font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
`;

const Actions = styled.div`
    align-items: center;
    display: flex;
    gap: 8px;
`;

export default class SelfServiceSelectionBar extends React.Component {
    render() {
        const items = this.props.items || [];
        if (!items.length) {
            return null;
        }
        const { roles, groups } = splitByType(items);
        const breakdown = countLabel(roles.length, groups.length);
        const label = `${items.length} selected${
            breakdown ? ` · ${breakdown}` : ''
        }`;
        return (
            <Bar data-testid='self-service-selection-bar'>
                <Count>{label}</Count>
                <Actions>
                    <Button
                        secondary
                        size='small'
                        onClick={this.props.onClear}
                        data-testid='clear-selection'
                    >
                        Clear selection
                    </Button>
                    {this.props.mode === 'leave' ? (
                        <Button
                            danger
                            size='small'
                            onClick={this.props.onPrimary}
                            data-testid='leave-selected'
                        >
                            Leave selected
                        </Button>
                    ) : (
                        <Button
                            size='small'
                            onClick={this.props.onPrimary}
                            data-testid='request-selected'
                        >
                            Request access
                        </Button>
                    )}
                </Actions>
            </Bar>
        );
    }
}
