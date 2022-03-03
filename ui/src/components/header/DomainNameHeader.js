/*
 * Copyright The Athenz Authors
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *      http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 *  distributed under the License is distributed on an "AS IS" BASIS,
 *  WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 *  See the License for the specific language governing permissions and
 *  limitations under the License.
 */
import styled from '@emotion/styled';
import React from 'react';
import { colors } from '../denali/styles';
import { withRouter } from 'next/router';
import Icon from '../denali/icons/Icon';
import { VIEW_PENDING_MEMBERS_BY_DOMAIN_TITLE } from '../constants/constants';
import PageUtils from '../utils/PageUtils';

const TitleDiv = styled.div`
    font: 600 20px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    margin-bottom: 10px;
    display: inline-block;
`;

const IconDiv = styled.div`
    margin-left: 10px;
    display: inline-block;
`;

class DomainNameHeader extends React.Component {
    constructor(props) {
        super(props);
    }

    render() {
        const { domainName, pendingCount } = this.props;
        let icon = 'notification';
        if (pendingCount > 0) {
            icon = 'notification-solid';
        }
        return (
            <div data-testid={'domain-name-header'}>
                <TitleDiv>{domainName}</TitleDiv>
                <IconDiv>
                    <Icon
                        icon={icon}
                        isLink
                        onClick={() =>
                            this.props.router.push({
                                pathname: PageUtils.workflowDomainPage(),
                                query: { domain: this.props.domainName },
                            })
                        }
                        size={'25px'}
                        color={colors.link}
                        enableTitle={true}
                        title={VIEW_PENDING_MEMBERS_BY_DOMAIN_TITLE}
                    />
                </IconDiv>
            </div>
        );
    }
}

export default withRouter(DomainNameHeader);
