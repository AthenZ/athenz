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
import Menu from '../denali/Menu/Menu';
import Icon from '../denali/icons/Icon';
import { colors } from '../denali/styles';
import {
    SERVICE_TYPE_STATIC,
    TOTAL_DYNAMIC_INSTANCES_LABEL,
    TOTAL_DYNAMIC_INSTANCES_DESC,
    TOTAL_STATIC_INSTANCES_DESC,
    TOTAL_HEALTHY_DYNAMIC_INSTANCES_LABEL,
    TOTAL_STATIC_INSTANCES_LABEL,
    TOTAL_HEALTHY_DYNAMIC_INSTANCES_DESC,
} from '../constants/constants';

const DomainSectionDiv = styled.div`
    margin: 20px 0;
`;

const DetailsDiv = styled.div`
    display: flex;
    flex-flow: row nowrap;
`;

const StyledAnchor = styled.a`
    color: #3570f4;
    text-decoration: none;
    cursor: pointer;
`;

const SectionDiv = styled.div`
    padding-right: 50px;
`;

const ValueDiv = styled.div`
    font-weight: 600;
`;
const LabelDiv = styled.div`
    color: #9a9a9a;
    text-decoration: none;
    font-size: 14px;
    cursor: pointer;
`;

const SubLabelDiv = styled.div`
    margin: 10px 10px;
`;

const HeaderMenuUserDiv = styled.div`
    margin-left: 15px;
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
    vertical-align: 2px;
`;

export default function ServiceInstanceDetails(props) {
    const { instanceDetailsMeta, categoryType } = props;

    return (
        <DomainSectionDiv>
            <DetailsDiv>
                {categoryType !== SERVICE_TYPE_STATIC && (
                    <span>
                        <SectionDiv>
                            <ValueDiv>
                                {instanceDetailsMeta.totalDynamic}
                            </ValueDiv>
                            <LabelDiv>
                                {TOTAL_DYNAMIC_INSTANCES_LABEL}
                                <SectionHeader>
                                    <Menu
                                        placement='bottom-end'
                                        trigger={({
                                            getTriggerProps,
                                            triggerRef,
                                        }) => (
                                            <Icon
                                                icon={'help-circle'}
                                                {...getTriggerProps({
                                                    innerRef: triggerRef,
                                                })}
                                                isLink
                                                size={'15px'}
                                                color={colors.graphBlue}
                                                enableTitle={false}
                                            />
                                        )}
                                        triggerOn='click'
                                    >
                                        <StyledAnchorDiv>
                                            {TOTAL_DYNAMIC_INSTANCES_DESC}
                                        </StyledAnchorDiv>
                                    </Menu>
                                </SectionHeader>
                            </LabelDiv>
                        </SectionDiv>
                    </span>
                )}

                {categoryType !== SERVICE_TYPE_STATIC && (
                    <span>
                        <SectionDiv>
                            <ValueDiv>
                                {instanceDetailsMeta.totalHealthyDynamic}
                            </ValueDiv>
                            <LabelDiv>
                                {TOTAL_HEALTHY_DYNAMIC_INSTANCES_LABEL}
                                <SectionHeader>
                                    <Menu
                                        placement='bottom-end'
                                        padding-left='10px'
                                        trigger={({
                                            getTriggerProps,
                                            triggerRef,
                                        }) => (
                                            <Icon
                                                icon={'help-circle'}
                                                {...getTriggerProps({
                                                    innerRef: triggerRef,
                                                })}
                                                isLink
                                                size={'15px'}
                                                color={colors.graphBlue}
                                                enableTitle={false}
                                            />
                                        )}
                                        triggerOn='click'
                                    >
                                        <StyledAnchorDiv>
                                            {
                                                TOTAL_HEALTHY_DYNAMIC_INSTANCES_DESC
                                            }
                                        </StyledAnchorDiv>
                                    </Menu>
                                </SectionHeader>
                            </LabelDiv>
                        </SectionDiv>
                    </span>
                )}

                {categoryType === SERVICE_TYPE_STATIC && (
                    <span>
                        <SectionDiv>
                            <ValueDiv>
                                {instanceDetailsMeta.totalStatic}
                            </ValueDiv>
                            <LabelDiv>
                                {TOTAL_STATIC_INSTANCES_LABEL}
                                <SectionHeader>
                                    <Menu
                                        placement='bottom-end'
                                        padding-left='10px'
                                        trigger={({
                                            getTriggerProps,
                                            triggerRef,
                                        }) => (
                                            <Icon
                                                icon={'help-circle'}
                                                {...getTriggerProps({
                                                    innerRef: triggerRef,
                                                })}
                                                isLink
                                                size={'15px'}
                                                color={colors.graphBlue}
                                                enableTitle={false}
                                            />
                                        )}
                                        triggerOn='click'
                                    >
                                        <StyledAnchorDiv>
                                            {TOTAL_STATIC_INSTANCES_DESC}
                                        </StyledAnchorDiv>
                                    </Menu>
                                </SectionHeader>
                            </LabelDiv>
                        </SectionDiv>
                    </span>
                )}
            </DetailsDiv>
        </DomainSectionDiv>
    );
}
