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
import DateUtils from '../utils/DateUtils';
import React from 'react';
import { connect } from 'react-redux';
import { selectTimeZone } from '../../redux/selectors/domains';

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

class CollectionDetails extends React.Component {
    constructor(props) {
        super(props);
    }

    render() {
        let localDate = new DateUtils();
        let modifiedDate = localDate.getLocalDate(
            this.props.collectionDetails.modified,
            this.props.timeZone,
            this.props.timeZone
        );
        let lastReviewedDate = this.props.collectionDetails.lastReviewedDate
            ? localDate.getLocalDate(
                  this.props.collectionDetails.lastReviewedDate,
                  this.props.timeZone,
                  this.props.timeZone
              )
            : 'N/A';
        return (
            <DomainSectionDiv data-testid='collection-details'>
                <DetailsDiv>
                    <SectionDiv>
                        <ValueDiv>{modifiedDate}</ValueDiv>
                        <LabelDiv>MODIFIED DATE</LabelDiv>
                    </SectionDiv>
                    {this.props.categroy !== 'policy' &&
                    this.props.categroy !== 'service' ? (
                        <SectionDiv>
                            <ValueDiv>{lastReviewedDate}</ValueDiv>
                            <LabelDiv>REVIEWED DATE</LabelDiv>
                        </SectionDiv>
                    ) : null}
                    {this.props.collectionDetails.description ? (
                        <SectionDiv>
                            <ValueDiv>
                                {this.props.collectionDetails.description}
                            </ValueDiv>
                            <LabelDiv>Description</LabelDiv>
                        </SectionDiv>
                    ) : null}
                </DetailsDiv>
                {this.props.category === 'policy' ? (
                    <SectionDiv>
                        <ValueDiv>
                            {this.props.collectionDetails.version}
                        </ValueDiv>
                        <LabelDiv>POLICY VERSION</LabelDiv>
                    </SectionDiv>
                ) : null}
            </DomainSectionDiv>
        );
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        timeZone: selectTimeZone(state),
    };
};

export default connect(mapStateToProps, null)(CollectionDetails);
