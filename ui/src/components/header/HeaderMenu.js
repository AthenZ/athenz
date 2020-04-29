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
import React from 'react';
import styled from '@emotion/styled';
import Menu from '../denali/Menu/Menu';
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';
import { Router } from '../../routes';

const HeaderMenuDiv = styled.div`
    display: flex;
`;

const MenuDiv = styled.div`
    min-width: 160px;
`;

const MenuItemDiv = styled.div`
    background-color: #fffff;
    display: block;
    padding: 12px 16px;
    white-space: nowrap;
`;

const StyledAnchorDiv = styled.div`
    color: #3570f4;
    text-decoration: none;
    cursor: pointer;
`;

const UserDropDownDiv = styled.div`
    background-color: #ffffff;
    border-radius: 4px;
    display: flex;
    flex-flow: row nowrap;
    justify-content: space-between;
    padding: 10px 15px;
    width: 350px;
`;

const UserDetailsDiv = styled.div`
    flex: 1 0;
    line-height: 1.5em;
`;

const UserHeaderDiv = styled.div`
    font: 600 16px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
`;

const UserEmailDiv = styled.div`
    color: #9a9a9a;
`;

const UserStreetLinkDiv = styled.div``;

const UserImageDiv = styled.div`
    flex: 0 0 100px;
`;

const StyledImg = styled.img`
    height: 100px;
    border-radius: 50%;
    width: 100px;
`;

const HeaderMenuUserDiv = styled.div`
    margin-left: 15px;
`;

export default (props) => {
    let icon = 'notification';
    if (props.pending) {
        if (Object.keys(props.pending).length !== 0) {
            icon = 'notification-solid';
        }
    }
    let menuItems =
        props.headerDetails &&
        props.headerDetails.headerLinks.map((headerLink, idx) => {
            return (
                <MenuItemDiv key={idx}>
                    <StyledAnchorDiv
                        data-testid='menu'
                        onClick={() =>
                            window.open(headerLink.url, headerLink.target)
                        }
                    >
                        {headerLink.title}
                    </StyledAnchorDiv>
                </MenuItemDiv>
            );
        });
    return (
        <HeaderMenuDiv data-testid='header-menu'>
            <Icon
                icon={icon}
                isLink
                onClick={() => Router.pushRoute('workflow')}
                size={'25px'}
                color={colors.white}
            />

            <HeaderMenuUserDiv>
                <Menu
                    placement='bottom-end'
                    trigger={({ getTriggerProps, triggerRef }) => (
                        <Icon
                            icon={'help-circle'}
                            {...getTriggerProps({ innerRef: triggerRef })}
                            isLink
                            size={'25px'}
                            color={colors.white}
                        />
                    )}
                    triggerOn='click'
                >
                    <MenuDiv>{menuItems}</MenuDiv>
                </Menu>
            </HeaderMenuUserDiv>
            {props.headerDetails && props.headerDetails.userId && (
                <HeaderMenuUserDiv>
                    <Menu
                        placement='bottom-end'
                        trigger={({ getTriggerProps, triggerRef }) => (
                            <Icon
                                icon={'user-profile-circle'}
                                {...getTriggerProps({ innerRef: triggerRef })}
                                isLink
                                size={'25px'}
                                color={colors.white}
                            />
                        )}
                        triggerOn='click'
                    >
                        <UserDropDownDiv>
                            <UserDetailsDiv>
                                <UserHeaderDiv>
                                    {props.headerDetails.userId}
                                </UserHeaderDiv>
                                <UserEmailDiv>
                                    {props.headerDetails.userData.userMail}
                                </UserEmailDiv>
                                <UserStreetLinkDiv>
                                    <StyledAnchorDiv
                                        data-testid='user-link'
                                        onClick={() =>
                                            window.open(
                                                props.headerDetails.userData
                                                    .userLink.url,
                                                props.headerDetails.userData
                                                    .userLink.target
                                            )
                                        }
                                    >
                                        {
                                            props.headerDetails.userData
                                                .userLink.title
                                        }
                                    </StyledAnchorDiv>
                                </UserStreetLinkDiv>
                            </UserDetailsDiv>
                            <UserImageDiv>
                                <StyledImg
                                    src={props.headerDetails.userData.userIcon}
                                />
                            </UserImageDiv>
                        </UserDropDownDiv>
                    </Menu>
                </HeaderMenuUserDiv>
            )}
        </HeaderMenuDiv>
    );
};
