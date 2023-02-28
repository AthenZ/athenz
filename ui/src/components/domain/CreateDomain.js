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
import { colors } from '../denali/styles';
import ButtonGroup from '../denali/ButtonGroup';
import Input from '../denali/Input';
import Switch from '../denali/Switch';
import Button from '../denali/Button';
import Color from '../denali/Color';
import RequestUtils from '../utils/RequestUtils';
import { withRouter } from 'next/router';
import { connect } from 'react-redux';
import { createSubDomain, createUserDomain } from '../../redux/thunks/domains';
import { selectPersonalDomain } from '../../redux/selectors/domains';
import { USER_DOMAIN } from '../constants/constants';

const TABS = [
    {
        label: 'Top Level',
        name: 'top-level',
    },
    {
        label: 'Sub Domain',
        name: 'sub-domain',
    },
    {
        label: 'Personal',
        name: 'personal',
    },
];

const SectionsDiv = styled.div`
    margin: 20px;
`;

const SectionDiv = styled.div`
    align-items: flex-start;
    display: flex;
    flex-flow: row nowrap;
    padding: 10px 30px;
`;

const LabelDiv = styled.div`
    flex: 0 0 150px;
    font-weight: 600;
    line-height: 36px;
`;

const ContentDiv = styled.div`
    flex: 1 1;
`;

const MessageDiv = styled.div`
    color: ${colors.grey600};
`;

const StyledInputDiv = styled.div`
    width: 500px;
`;

const SliderDiv = styled.div`
    vertical-align: middle;
`;

const AuditEnabledLabel = styled.label`
    color: ${colors.grey600};
    margin-left: 5px;
    white-space: nowrap;
    font: 300 14px HelveticaNeue-Reg, Helvetica, Arial, sans-serif;
`;

const LineSeparatorDiv = styled.div`
    border-bottom: 1px solid ${colors.grey500};
    margin-top: 10px;
    margin-bottom: 10px;
    width: 100%;
`;

class CreateDomain extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            selected: 'top-level',
            domain: '',
            subDomain: '',
        };
        this.tabClicked = this.tabClicked.bind(this);
        this.onSubmit = this.onSubmit.bind(this);
    }

    tabClicked(tab) {
        let pdom = 'home.' + this.props.userId;
        switch (tab.name) {
            case 'personal':
                if (this.props.personalDomain) {
                    this.props.router.push(`/domain/${pdom}/role`);
                } else {
                    this.props
                        .createUserDomain(this.props.userId, this.props._csrf)
                        .then(() => {
                            this.props.router.push(`/domain/${pdom}/role`);
                        })
                        .catch((err) => {
                            this.setState({
                                errorMessage:
                                    RequestUtils.xhrErrorCheckHelper(err),
                            });
                        });
                }
                break;
            case 'sub-domain':
                this.setState({
                    selected: 'sub-domain',
                });
                break;
            case 'top-level':
            default:
                this.setState({
                    selected: 'top-level',
                });
        }
    }

    inputChanged(key, evt) {
        evt.preventDefault();
        this.setState({
            [key]: evt.target.value,
        });
    }

    onSubmit() {
        this.props
            .createSubDomain(
                this.state.domain,
                this.state.subDomain,
                `${USER_DOMAIN}.${this.props.userId}`,
                this.props._csrf
            )
            .then(() => {
                this.props.router.push(
                    `/domain/${this.state.domain}.${this.state.subDomain}/role`
                );
            })
            .catch((err) => {
                this.setState({
                    errorMessage: RequestUtils.xhrErrorCheckHelper(err),
                });
            });
    }

    render() {
        let domainDescription = '';
        let firstSection = '';
        let secondSection = '';
        let firstLabel = '';
        let secondLabel = '';
        let isDisabled = true;

        let createDomainMessage = this.props.createDomainMessage
            .split('\n')
            .map((item, i) => {
                return <p key={i}>{item}</p>;
            });

        if (this.state.selected === 'top-level') {
            domainDescription = (
                <ContentDiv>
                    <MessageDiv>{createDomainMessage}</MessageDiv>
                </ContentDiv>
            );
            firstSection = (
                <ContentDiv>
                    <StyledInputDiv>
                        <Input
                            placeholder={'Enter Domain Name'}
                            disabled={true}
                            readOnly={true}
                            fluid={true}
                            value={''}
                        />
                    </StyledInputDiv>
                </ContentDiv>
            );
            secondSection = (
                <ContentDiv>
                    <SliderDiv>
                        <Switch
                            checked={false}
                            disabled={true}
                            name={'auditEnabled'}
                        />
                        <AuditEnabledLabel>Audit Enabled</AuditEnabledLabel>
                    </SliderDiv>
                </ContentDiv>
            );
            firstLabel = 'Domain Name';
        } else if (this.state.selected === 'sub-domain') {
            domainDescription = (
                <ContentDiv>
                    <MessageDiv>
                        A subdomain can be created by any admin of the parent
                        domain.
                        <br />
                        <br />
                        A subdomain is completely partitioned from its parent
                        domain and shares no inheritance.
                        <br />
                        <br />
                    </MessageDiv>
                </ContentDiv>
            );
            firstSection = (
                <ContentDiv>
                    <StyledInputDiv>
                        <Input
                            placeholder={'Enter an existing domain'}
                            fluid={true}
                            id={'domain'}
                            onChange={this.inputChanged.bind(this, 'domain')}
                            value={this.state.domain ? this.state.domain : ''}
                        />
                    </StyledInputDiv>
                </ContentDiv>
            );
            secondSection = (
                <ContentDiv>
                    <StyledInputDiv>
                        <Input
                            placeholder={'Enter a new sub-domain'}
                            fluid={true}
                            id={'subDomain'}
                            onChange={this.inputChanged.bind(this, 'subDomain')}
                            value={
                                this.state.subDomain ? this.state.subDomain : ''
                            }
                        />
                    </StyledInputDiv>
                </ContentDiv>
            );
            firstLabel = 'Parent Domain';
            secondLabel = 'Sub Domain Name';
            isDisabled = false;
        }

        return (
            <SectionsDiv data-testid='create-domain-component'>
                <SectionDiv>
                    <LabelDiv>Domain Type</LabelDiv>
                    <ContentDiv>
                        <ButtonGroup
                            buttons={TABS}
                            selectedName={this.state.selected}
                            onClick={this.tabClicked}
                        />
                    </ContentDiv>
                </SectionDiv>
                <SectionDiv>
                    <LabelDiv />
                    {domainDescription}
                </SectionDiv>
                <SectionDiv>
                    <LabelDiv>{firstLabel}</LabelDiv>
                    {firstSection}
                </SectionDiv>
                <SectionDiv>
                    <LabelDiv>{secondLabel}</LabelDiv>
                    {secondSection}
                </SectionDiv>
                <SectionDiv>
                    <LabelDiv />
                    <ContentDiv>
                        <LineSeparatorDiv />
                    </ContentDiv>
                </SectionDiv>
                <SectionDiv>
                    <LabelDiv />
                    <ContentDiv>
                        {this.state.errorMessage && (
                            <Color name={'red600'}>
                                {this.state.errorMessage}
                            </Color>
                        )}
                        <div>
                            <Button
                                type={'button'}
                                disabled={isDisabled}
                                onClick={this.onSubmit}
                            >
                                Submit
                            </Button>
                            <Button
                                secondary={true}
                                type={'button'}
                                disabled={isDisabled}
                            >
                                Cancel
                            </Button>
                        </div>
                    </ContentDiv>
                </SectionDiv>
            </SectionsDiv>
        );
    }
}
const mapStateToProps = (state, props) => {
    return {
        ...props,
        personalDomain: selectPersonalDomain(state, 'home.' + props.userId),
    };
};

const mapDispatchToProps = (dispatch) => ({
    createSubDomain: (parentDomain, domain, adminUser, _csrf) =>
        dispatch(createSubDomain(parentDomain, domain, adminUser, _csrf)),
    createUserDomain: (userId, _csrf) =>
        dispatch(createUserDomain(userId, _csrf)),
});

export default connect(
    mapStateToProps,
    mapDispatchToProps
)(withRouter(CreateDomain));
