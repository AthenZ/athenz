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
import DateUtils from '../utils/DateUtils';
import React from 'react';
import { MODAL_TIME_OUT } from '../constants/constants';

const DomainSectionDiv = styled.div`
    margin: 20px 0;
`;

const DetailsDiv = styled.div`
    display: flex;
    flex-flow: row nowrap;
`;

const SectionDiv = styled.div`
    padding-right: 50px;
`;

const ValueDiv = styled.div`
    font-weight: 600;
`;

const LabelDiv = styled.div`
    color: #9a9a9a;
    font-size: 12px;
    text-transform: uppercase;
`;

const StyledAnchorDiv = styled.div`
    color: #3570f4;
    text-decoration: none;
    cursor: pointer;
`;

export default class RoleDetails extends React.Component {
    constructor(props) {
        super(props);
        this.api = props.api;
    }

    render() {
        let localDate = new DateUtils();
        let modifiedDate = localDate.getLocalDate(
            this.props.roleDetails.modified,
            'UTC',
            'UTC'
        );
        let lastReviewedDate = this.props.roleDetails.lastReviewedDate
            ? localDate.getLocalDate(
                  this.props.roleDetails.lastReviewedDate,
                  'UTC',
                  'UTC'
              )
            : 'N/A';
        return (
            <DomainSectionDiv data-testid='role-details'>
                <DetailsDiv>
                    <SectionDiv>
                        <ValueDiv>{modifiedDate}</ValueDiv>
                        <LabelDiv>MODIFIED DATE</LabelDiv>
                    </SectionDiv>
                    <SectionDiv>
                        <ValueDiv>{lastReviewedDate}</ValueDiv>
                        <LabelDiv>REVIEWED DATE</LabelDiv>
                    </SectionDiv>
                </DetailsDiv>
            </DomainSectionDiv>
        );
    }
}
