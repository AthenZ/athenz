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
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';
import ServiceDependencyResGroupRoles from './ServiceDependencyResGroupRoles';

const TDStyledResGroup = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 35px;
    vertical-align: middle;
    word-break: break-all;
`;

const TDStyledRole = styled.td`
    background-color: ${(props) => props.color};
    text-align: ${(props) => props.align};
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
    overflow: 'auto';
`;

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

const TableThStyled = styled.th`
    height: 25px;
    margin-left: 10px;
    margin-top: 10px;
    text-align: left;
    padding: 5px 0 5px 15px;
    vertical-align: middle;
    word-break: break-all;
    font-weight: lighter;
    display: block;
`;

const LeftMarginSpan = styled.span`
    margin-right: 10px;
    verticalalign: bottom;
`;

const TableHeadStyledRsGroupName = styled.th`
    text-align: ${(props) => props.align};
    border-bottom: 2px solid #d5d5d5;
    color: #9a9a9a;
    font-weight: 600;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0 5px 35px;
    word-break: break-all;
    width: 50%;
`;

const TableHeadStyled = styled.th`
    text-align: ${(props) => props.align};
    border-bottom: 2px solid #d5d5d5;
    color: #9a9a9a;
    font-weight: 600;
    padding-bottom: 5px;
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0 5px 15px;
    word-break: break-all;
    width: 50%;
`;

export default class ServiceDependency extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            dependency: props.dependency,
            expanded: false,
            disabled:
                !props.dependency.resourceGroups ||
                props.dependency.resourceGroups.length <= 0,
        };
        this.expandResourceGroups = this.expandResourceGroups.bind(this);
    }

    expandResourceGroups() {
        if (!this.state.disabled) {
            this.setState({
                expanded: !this.state.expanded,
            });
        }
    }

    render() {
        const arrowup = 'arrowhead-up-circle-solid';
        const arrowdown = 'arrowhead-down-circle';
        let length;
        const left = 'left';
        let toReturn = [];
        let service = this.state.dependency
            ? this.state.dependency.service
            : '';
        if (!this.state.disabled) {
            length = this.prepareResourceGroups(service, toReturn);
        }

        if (!this.state.expanded) {
            return (
                <StyleTable data-testid='dependency-sgroup-table'>
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
                                        onClick={this.expandResourceGroups}
                                        color={
                                            this.state.disabled
                                                ? colors.grey500
                                                : colors.icons
                                        }
                                        isLink
                                        size={'1.25em'}
                                        verticalAlign={'text-bottom'}
                                    />
                                </LeftMarginSpan>
                                {this.state.disabled
                                    ? `${service}`
                                    : `${service} (${length})`}
                            </TableThStyled>
                        </tr>
                    </thead>
                </StyleTable>
            );
        }

        return (
            <StyleTable
                key='dependency-sgroup-table'
                data-testid='dependencySgroupTable'
            >
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
                                    onClick={this.expandResourceGroups}
                                    color={colors.icons}
                                    isLink
                                    size={'1.25em'}
                                    verticalAlign={'text-bottom'}
                                />
                            </LeftMarginSpan>
                            {`${service} (${length})`}
                        </TableThStyled>
                    </tr>
                    <tr>
                        <TableHeadStyledRsGroupName align={left}>
                            Resource Group
                        </TableHeadStyledRsGroupName>
                        <TableHeadStyled align={left}>Role</TableHeadStyled>
                    </tr>
                </thead>
                <tbody>{toReturn}</tbody>
            </StyleTable>
        );
    }

    prepareResourceGroups(service, toReturn) {
        let length = 0;
        const left = 'left';
        let resGroupMap = this.state.dependency.resourceGroups.reduce(function (
            map,
            obj
        ) {
            // Extract the provider, resource group and role to create the role the resource group and role tags.
            // For example:
            // service - paranoids.ppse.ckms.ykeykey_alpha
            // obj - ykeykey_alpha.tenant.home.olevi.res_group.test_res_grp1.writers
            // Then the resource group will be 'test_res_grp1', the role will be 'writers' and the link will be:
            // "/domain/paranoids.ppse.ckms/role/ykeykey_alpha.tenant.home.olevi.res_group.test_res_grp1.writers/policy";
            let resGroupIndexStart = obj.indexOf('.res_group.') + 11;
            let resGroupIndexEnd = obj.indexOf('.', resGroupIndexStart);
            let resGroupRoleStart = obj.indexOf('.', resGroupIndexEnd) + 1;
            let resourceGroup = obj.substring(
                resGroupIndexStart,
                resGroupIndexEnd
            );
            let resourceGroupRole = obj.substring(resGroupRoleStart);
            let providerService = service.substring(
                0,
                service.lastIndexOf('.')
            );
            let roleLink =
                '/domain/' + providerService + '/role/' + obj + '/policy';

            if (!map[resourceGroup]) {
                map[resourceGroup] = [];
                length++;
            }
            map[resourceGroup].push({
                resourceGroup: resourceGroup,
                resourceGroupRole: resourceGroupRole,
                roleLink: roleLink,
            });
            return map;
        },
        {});

        let color = '';
        for (const [key, value] of Object.entries(resGroupMap)) {
            if (color === '') {
                color = colors.row;
            } else {
                color = '';
            }
            toReturn.push(
                <tr key={this.state.dependency.service + ';' + key}>
                    <TDStyledResGroup align={left} color={color}>
                        {key}
                    </TDStyledResGroup>
                    <TDStyledRole align={left} color={color}>
                        <ServiceDependencyResGroupRoles details={value} />
                    </TDStyledRole>
                </tr>
            );
        }
        return length;
    }
}
