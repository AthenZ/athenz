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
import styled from '@emotion/styled';
import React from 'react';
import Link from 'next/link';
import PageUtils from '../utils/PageUtils';
import Menu from '../denali/Menu/Menu';
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';
import { selectDynamicServiceHeaderDetails } from '../../redux/selectors/services';
import { connect } from 'react-redux';

const StyledAnchor = styled.a`
    color: #3570f4;
    text-decoration: none;
    cursor: pointer;
`;

const TitleDiv = styled.div`
    font: 600 20px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    margin-bottom: 10px;
`;

const StyledAnchorDiv = styled.div`
    color: #9a9a9a;
    text-decoration: none;
    font-size: 14px;
    cursor: pointer;
    margin: 15px 15px;
`;

const SectionHeader = styled.span`
    margin: 3px;
    vertical-align: 3px;
`;

export default function ServiceNameHeader(props) {
    const { domain, service, serviceHeaderDetails } = props;

    let link = (
        <Link href={PageUtils.servicePage(domain)} passHref legacyBehavior>
            <StyledAnchor>{domain}</StyledAnchor>
        </Link>
    );

    let message = [serviceHeaderDetails.description];

    if (serviceHeaderDetails.url != '') {
        message.push(' For more information click ');
        var urlLink = (
            <StyledAnchor
                key={Date.now()}
                onClick={() =>
                    window.open(
                        serviceHeaderDetails.url,
                        serviceHeaderDetails.target
                    )
                }
            >
                here
            </StyledAnchor>
        );
        message.push(urlLink);
    }

    return (
        <TitleDiv data-testid='service-name-header'>
            {link}:service.{service}
            <SectionHeader>
                <Menu
                    placement='bottom-end'
                    padding-bottom='10px'
                    trigger={({ getTriggerProps, triggerRef }) => (
                        <Icon
                            icon={'help-circle'}
                            {...getTriggerProps({ innerRef: triggerRef })}
                            isLink
                            size={'15px'}
                            color={colors.graphBlue}
                            enableTitle={false}
                        />
                    )}
                    triggerOn='click'
                >
                    <StyledAnchorDiv>{message}</StyledAnchorDiv>
                </Menu>
            </SectionHeader>
        </TitleDiv>
    );
}
