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
 * See the License for the specific language governing permissions and limitations
 * under the License.
 */
import React from 'react';
import styled from '@emotion/styled';
import { connect } from 'react-redux';
import Menu from '../denali/Menu/Menu';
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';
import { selectResourceOwnershipUi } from '../../redux/selectors/domains';
import {
    DEFAULT_RESOURCE_OWNERSHIP_UI,
    getManagedIconTooltip,
    resolveResourceOwnershipUi,
} from '../utils/resourceOwnershipUi';

const MenuDiv = styled.div`
    padding: 5px 10px;
    background-color: black;
    color: white;
    font-size: 12px;
`;

export function ManagedResourceIcon(props) {
    if (!props.show) {
        return null;
    }
    const ui = resolveResourceOwnershipUi(props.resourceOwnershipUi);
    const label =
        props.tooltip !== undefined && props.tooltip !== null
            ? props.tooltip
            : getManagedIconTooltip(ui);
    const iconName = ui.icon || DEFAULT_RESOURCE_OWNERSHIP_UI.icon;

    return (
        <Menu
            placement='bottom-start'
            trigger={
                <span>
                    <Icon
                        dataWdio={'resource-ownership-managed'}
                        icon={iconName}
                        color={colors.icons}
                        isLink
                        size={props.size || '1.25em'}
                        verticalAlign={'text-bottom'}
                        viewBoxWidth='24'
                        viewBoxHeight='24'
                        enableTitle={false}
                    />
                </span>
            }
        >
            <MenuDiv>{label}</MenuDiv>
        </Menu>
    );
}

const mapStateToProps = (state, ownProps) => ({
    resourceOwnershipUi:
        ownProps.resourceOwnershipUi !== undefined
            ? ownProps.resourceOwnershipUi
            : selectResourceOwnershipUi(state),
});

export default connect(mapStateToProps)(ManagedResourceIcon);
