/*
 * Copyright 2020 Verizon Media
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
import styled from '@emotion/styled';
import React from 'react';
import Menu from '../denali/Menu/Menu';
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';
import { Link } from '../../routes';
import { withRouter } from 'next/router';

const StyledAnchor = styled.a`
    color: #3570f4;
    text-decoration: none;
    cursor: pointer;
`;

const TitleDiv = styled.div`
    font: 600 20px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    margin-bottom: 10px;
`;

const MenuDiv = styled.div`
    padding: 5px 10px;
    background-color: black;
    color: white;
    font-size: 12px;
`;

class NameHeader extends React.Component {
    constructor(props) {
        super(props);
    }

    render() {
        const { domain, collectionDetails, collection } = this.props;

        let iconDelegated = (
            <Menu
                placement='bottom-start'
                trigger={
                    <span>
                        <Icon
                            icon={'network'}
                            color={colors.icons}
                            isLink
                            size={'1.25em'}
                            verticalAlign={'text-bottom'}
                        />
                    </span>
                }
            >
                <MenuDiv>Delegated Role</MenuDiv>
            </Menu>
        );

        let iconAudit = (
            <Menu
                placement='bottom-start'
                trigger={
                    <span>
                        <Icon
                            icon={'file-search'}
                            color={colors.icons}
                            isLink
                            size={'1.25em'}
                            verticalAlign={'text-bottom'}
                            onHover={'audit enabled role'}
                        />
                    </span>
                }
            >
                <MenuDiv>Audit Enabled {this.props.category}</MenuDiv>
            </Menu>
        );

        let roleTypeIcon = collectionDetails.trust ? iconDelegated : '';
        let roleAuditIcon = collectionDetails.auditEnabled ? iconAudit : '';

        if (collectionDetails.trust) {
            let deDomain = collectionDetails.trust;
            return (
                <TitleDiv data-testid='collection-name-header'>
                    {roleTypeIcon}
                    {roleAuditIcon}
                    <StyledAnchor
                        onClick={() =>
                            this.props.router.push(
                                `/domain/${domain}/role`,
                                `/domain/${domain}/role`,
                                { getInitialProps: true }
                            )
                        }
                    >
                        {domain}
                    </StyledAnchor>
                    :role.{collection}
                    {' (Delegated to '}
                    <StyledAnchor
                        onClick={() =>
                            this.props.router.push(
                                `/domain/${deDomain}/role`,
                                `/domain/${deDomain}/role`,
                                { getInitialProps: true }
                            )
                        }
                    >
                        {deDomain}
                    </StyledAnchor>
                    {' )'}
                </TitleDiv>
            );
        }
        let link;
        if (this.props.category === 'group') {
            link = (
                <StyledAnchor
                    onClick={() =>
                        this.props.router.push(
                            `/domain/${domain}/group`,
                            `/domain/${domain}/group`,
                            { getInitialProps: true }
                        )
                    }
                >
                    {domain}
                </StyledAnchor>
            );
        } else if (this.props.category === 'role') {
            link = (
                <StyledAnchor
                    onClick={() =>
                        this.props.router.push(
                            `/domain/${domain}/role`,
                            `/domain/${domain}/role`,
                            { getInitialProps: true }
                        )
                    }
                >
                    {domain}
                </StyledAnchor>
            );
        }

        return (
            <TitleDiv data-testid='collection-name-header'>
                {roleTypeIcon}
                {roleAuditIcon}
                {link}:{this.props.category}.{collection}
            </TitleDiv>
        );
    }
}

export default withRouter(NameHeader);
