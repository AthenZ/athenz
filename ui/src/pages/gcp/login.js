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
import Button from '../../components/denali/Button';
import API from '../../api';
import Error from '../_error';
import styled from '@emotion/styled';
import createCache from '@emotion/cache';
import RequestUtils from '../../components/utils/RequestUtils';
import { selectIsLoading } from '../../redux/selectors/loading';
import { selectUserResourceAccessList } from '../../redux/selectors/user';
import { getUserResourceAccessList } from '../../redux/thunks/user';
import { connect } from 'react-redux';
import { CacheProvider } from '@emotion/react';
import { ReduxPageLoader } from '../../components/denali/ReduxPageLoader';
import { USER_DOMAIN } from '../../components/constants/constants';

const GcpHeader = styled.header`
    border-bottom: 1px solid lightgray;
    margin: 10px;
    margin-bottom: 20px;
`;

const ParentWrapperDiv = styled.div`
    max-width: 800px;
    margin: 0 auto;
`;

const StyledP = styled.p`
    font-size: 16px;
`;

const RadioButtonsContainer = styled.div`
    display: flex;
    flex-direction: column;
    margin-top: 10px;
    margin-bottom: 10px;
    margin-left: 20px;
    font-weight: bold;
`;

const ProjectTitleDiv = styled.div`
    font-size: 18px;
    display: inline;
    border-bottom: 1px solid lightgray;
    margin-bottom: 10px;
    padding: 10px;
    width: 100%;
    display: block;
`;

const RadioButton = styled.input`
    vertical-align: middle;
    width: 18px;
    height: 18px;
    margin: 10px;
`;

const ProjectLabel = styled.label`
    margin: 0;
    font-weight: bold;
    font-size: 16px;
    color: #000;
    vertical-align: middle;
`;

const SubmitContainer = styled.div`
    display: flex;
`;

function getAssertionsFromResourceAccessList(resourceAccessList, userAuthority) {
    let assertionsList = [];
    if (resourceAccessList.resources) {
        resourceAccessList.resources.forEach(function (resources) {
            resources.assertions.forEach(function (assertion) {
                if (userAuthority === 'all') {
                    assertionsList.push(assertion);
                    return;
                }
                if (assertion.role.toLowerCase().indexOf('admin') > -1) {
                    if (userAuthority === 'admin') {
                        assertionsList.push(assertion);
                    }
                } else if (userAuthority === 'dev') {
                    assertionsList.push(assertion);
                }
            });
        });
    }
    return assertionsList;
}

function getProjectDomainName(role) {
    let projectDomainNameAndRole = role.split(':role.');
    let projectDomainName = projectDomainNameAndRole[0];
    if (!projectDomainName) return '';
    return projectDomainName;
}

function getRoleName(role) {
    let projectDomainNameAndRole = role.split(':role.');
    if (projectDomainNameAndRole.length < 1) return '';
    let roleName = projectDomainNameAndRole[1];
    return roleName;
}

function getProjectID(resource) {
    let splitStrings = resource.split('/');
    if (
        splitStrings.length < 4 ||
        splitStrings[0] !== 'projects' ||
        splitStrings[2] !== 'roles'
    )
        return '';
    let projectID = splitStrings[1];
    return projectID;
}

export async function getServerSideProps(context) {
    const api = API(context.req);
    let reload = false;
    let notFound = false;
    let error = null;
    const domains = await Promise.all([api.getForm()]).catch((err) => {
        let response = RequestUtils.errorCheckHelper(err);
        reload = response.reload;
        error = response.error;
        return [{}];
    });

    let queryParams = context.query || {};
    let isAdmin = queryParams.isAdmin === 'true';
    let userAuthority = queryParams.userAuthority || 'dev';
    let startPath = queryParams.startPath || '';
    let projectDomainName = queryParams.projectDomainName || '';
    let validationError = queryParams.validationError || '';
    return {
        props: {
            reload,
            notFound,
            error,
            validationError,
            isAdmin,
            startPath,
            userAuthority,
            projectDomainName,
            _csrf: domains[0],
        },
    };
}

class GCPLoginPage extends React.Component {
    constructor(props) {
        super(props);
        this.api = API();
        this.cache = createCache({
            key: 'athenz',
            nonce: this.props.nonce,
        });
        this.state = {
            errorMessage: '',
            projectRoleMap: {},
            roleName: '',
        };
        this.getAssertionList = this.getAssertionList.bind(this);
        this.populateProjectRoleMap = this.populateProjectRoleMap.bind(this);
        this.showError = this.showError.bind(this);
    }

    componentDidMount() {
        const { getResourceAccessList } = this.props;
        Promise.all([
            getResourceAccessList({
                action: 'gcp.assume_role',
            }),
        ]).catch((err) => {
            this.showError(RequestUtils.fetcherErrorCheckHelper(err));
        });
    }

    componentDidUpdate(prevProps) {
        const { resourceAccessList } = this.props;
        if (prevProps && prevProps.resourceAccessList !== resourceAccessList) {
            let assertionList = this.getAssertionList();
            this.populateProjectRoleMap(assertionList);
        }
    }

    showError(errorMessage) {
        this.setState((prevState) => ({
            ...prevState,
            errorMessage: errorMessage,
        }));
    }

    getAssertionList() {
        const { resourceAccessList, isAdmin, projectDomainName, userAuthority } = this.props;
        let assertionsList = getAssertionsFromResourceAccessList(
            resourceAccessList,
            userAuthority
        );
        // filter project list if projectDomainName is specified in the query
        if (projectDomainName) {
            assertionsList = assertionsList.filter(
                (assertion) => assertion.role.indexOf(projectDomainName) > -1
            );
        }
        return assertionsList;
    }

    populateProjectRoleMap(assertionsList) {
        let projectRoleMap = {};
        assertionsList.forEach((assertion) => {
            let projectName = getProjectDomainName(assertion.role);
            let projectRoleName = getRoleName(assertion.role);
            let projectID = getProjectID(assertion.resource);
            if (!projectName || !projectRoleName || !projectID) {
                return;
            }
            let project = {
                roleName: assertion.role, // value passed to gcp
                projectRoleName, // For UI readability
                projectName, // For UI readability
                projectID, // For UI readability
            };
            if (!projectRoleMap[projectName]) {
                projectRoleMap[projectName] = [project];
            } else {
                projectRoleMap[projectName].push(project);
            }
        });
        this.setState((prevState) => ({
            ...prevState,
            projectRoleMap,
        }));
    }

    handleRadioButton(projectObject) {
        this.setState((prevState) => ({
            ...prevState,
            roleName: projectObject.roleName,
        }));
    }

    render() {
        let errorMessage = this.props.error || this.state.errorMessage;
        if (this.props.reload) {
            window.location.reload();
            return <div />;
        }
        if (errorMessage) {
            return <Error err={errorMessage} />;
        }
        let displayProjects = [];
        for (let pName in this.state.projectRoleMap) {
            let projectRoleNames = [];
            let projectID = this.state.projectRoleMap[pName][0].projectID;
            this.state.projectRoleMap[pName].forEach((projectObject, index) => {
                projectRoleNames.push(
                    <div key={index}>
                        <ProjectLabel key={'label-' + projectObject.roleName}>
                            <RadioButton
                                type={'radio'}
                                key={'button-' + projectObject.roleName}
                                value={projectObject.roleName}
                                name={'project'}
                                checked={
                                    this.state.roleName ===
                                    projectObject.roleName
                                }
                                onChange={() =>
                                    this.handleRadioButton(projectObject)
                                }
                                required={true}
                            />
                            {projectObject.projectRoleName}
                        </ProjectLabel>
                    </div>
                );
            });

            displayProjects.push(
                <div>
                    <ProjectTitleDiv key={'project-name-' + pName}>
                        Project: {projectID} ({pName})
                    </ProjectTitleDiv>
                    <RadioButtonsContainer
                        key={'radio-button-container-' + pName}
                    >
                        {projectRoleNames}
                    </RadioButtonsContainer>
                </div>
            );
        }

        let gcpLoginContainer = displayProjects.length ? (
            <div data-testid='gcp-login'>
                <GcpHeader>
                    <img src='/static/google-cloud.svg'></img>
                </GcpHeader>
                <ParentWrapperDiv>
                    <form action='/gcp/login/post' method='post'>
                        <input
                            type='hidden'
                            name='_csrf'
                            value={this.props._csrf}
                        ></input>
                        <input
                            type='hidden'
                            name='userAuthority'
                            value={this.props.userAuthority}
                        ></input>
                        <input
                            type='hidden'
                            name='startPath'
                            value={this.props.startPath}
                        ></input>
                        <StyledP>Select a role:</StyledP>
                        {displayProjects}
                        <SubmitContainer>
                            <Button type={'submit'}>Submit</Button>
                        </SubmitContainer>
                    </form>
                </ParentWrapperDiv>
            </div>
        ) : (
            <div data-testid='gcp-login-error'>
                <GcpHeader>
                    <img src='/static/google-cloud.svg'></img>
                </GcpHeader>
                <ParentWrapperDiv>
                    <h3>
                        Error: There are no GCP project roles associated with
                        your account.
                    </h3>
                    <p>
                        Check to make sure that your <tt>gcp.*</tt> roles
                        contain your user. Your account should be in the
                        configured federated roles that have access to the
                        project. If that does not work, please ask your Athenz
                        domain admin for assistance.
                    </p>
                </ParentWrapperDiv>
            </div>
        );
        return this.props.isLoading.length !== 0 ? (
            <ReduxPageLoader message={'Loading GCP Projects'} />
        ) : (
            <CacheProvider value={this.cache}>
                {gcpLoginContainer}
            </CacheProvider>
        );
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        isLoading: selectIsLoading(state),
        resourceAccessList: selectUserResourceAccessList(state),
    };
};

const mapDispatchToProps = (dispatch) => ({
    getResourceAccessList: (action) =>
        dispatch(getUserResourceAccessList(action)),
});

export default connect(mapStateToProps, mapDispatchToProps)(GCPLoginPage);
