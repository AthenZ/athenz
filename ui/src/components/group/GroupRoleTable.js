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
import RoleGroup from '../role/RoleGroup';
import { GROUP_ROLES_CATEGORY } from '../constants/constants';
import { selectIsLoading } from '../../redux/selectors/loading';
import { connect } from 'react-redux';
import { ReduxPageLoader } from '../denali/ReduxPageLoader';
import {selectTimeZone} from "../../redux/selectors/domains";

const StyleTable = styled.div`
    width: 100%;
    border-spacing: 0 15px;
    display: table;
    border-collapse: separate;
    border-color: grey;
`;

const GroupRoleDiv = styled.div`
    padding-top: 20px;
`;

const TableHeadStyled = styled.div`
    border-bottom: 2px solid rgb(213, 213, 213);
    color: rgb(154, 154, 154);
    vertical-align: top;
    text-transform: uppercase;
    padding: 5px 0px 5px 15px;
    word-break: break-all;
    display: flex;
`;

const TableHeadStyledLabel = styled.div`
    text-align: ${(props) => props.align};
    width: ${(props) => props.width};
`;

class GroupRoleTable extends React.Component {
    constructor(props) {
        super(props);
        let subRows = [];

        if (props.prefixes) {
            props.prefixes.forEach((prefix) => {
                let rows = props.roles.filter(
                    (item) => item.domainName == prefix
                );
                subRows[prefix] = rows;
            });
        }

        this.state = {
            roles: props.roles || [],
            rows: subRows,
        };
    }

    componentDidUpdate = (prevProps) => {
        if (prevProps.domain !== this.props.domain) {
            this.setState({
                rows: {},
            });
        } else if (prevProps.roles !== this.props.roles) {
            let subRows = [];
            if (this.props.prefixes) {
                this.props.prefixes.forEach((prefix) => {
                    let rows = this.props.roles.filter(
                        (item) => item.domainName == prefix
                    );
                    subRows[prefix] = rows;
                });
            }

            this.setState({
                roles: this.props.roles || [],
                rows: subRows,
            });
        }
    };

    render() {
        const center = 'center';
        const left = 'left';
        const { domain } = this.props;
        let rows = [];

        if (this.state.roles && this.state.roles.length > 0) {
            if (this.state.rows) {
                for (let name in this.state.rows) {
                    // group rows
                    let roleGroup = (
                        <RoleGroup
                            category={GROUP_ROLES_CATEGORY}
                            key={'group-role:' + name}
                            domain={name}
                            name={name}
                            roles={this.state.rows[name]}
                            onUpdateSuccess={this.props.onSubmit}
                            _csrf={this.props._csrf}
                            timeZone={this.props.timeZone}
                        />
                    );
                    rows.push(roleGroup);
                }
            }
        }

        if (!this.props.displayTable) {
            return (
                <GroupRoleDiv>
                    The group isn't a member of any role.
                </GroupRoleDiv>
            );
        }

        return this.props.isLoading.length !== 0 ? (
            <ReduxPageLoader message={'Loading group data'} />
        ) : (
            <StyleTable key='role-table' data-testid='roletable'>
                <TableHeadStyled>
                    <TableHeadStyledLabel align={left} width={'50%'}>
                        Role
                    </TableHeadStyledLabel>
                    <TableHeadStyledLabel align={left} width={'25%'}>
                        Expiry Date
                    </TableHeadStyledLabel>
                    <TableHeadStyledLabel align={center} width={'25%'}>
                        Members
                    </TableHeadStyledLabel>
                </TableHeadStyled>
                <GroupRoleDiv>{rows}</GroupRoleDiv>
            </StyleTable>
        );
    }
}

const mapStateToProps = (state, props) => {
    return {
        ...props,
        isLoading: selectIsLoading(state),
        timeZone: selectTimeZone(state),

    };
};

export default connect(mapStateToProps)(GroupRoleTable);
