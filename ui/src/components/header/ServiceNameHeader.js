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
import Link from 'next/link';
import { withRouter } from 'next/router';
import PageUtils from '../utils/PageUtils';

const StyledAnchor = styled.a`
    color: #3570f4;
    text-decoration: none;
    cursor: pointer;
`;

const TitleDiv = styled.div`
    font: 600 20px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
    margin-bottom: 10px;
`;

class ServiceNameHeader extends React.Component {
    constructor(props) {
        super(props);
    }

    render() {
        const { domain, service } = this.props;

        let link = (
            <Link href={PageUtils.servicePage(domain)}>
                <StyledAnchor>{domain}</StyledAnchor>
            </Link>
        );

        return (
            <TitleDiv data-testid='service-name-header'>
                {link}:service.{service}
            </TitleDiv>
        );
    }
}

export default withRouter(ServiceNameHeader);
