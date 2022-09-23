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
import SearchInput from '../denali/SearchInput';
import { withRouter } from 'next/router';

class Search extends React.Component {
    constructor(props) {
        super(props);
        this.state = {
            selected: this.props.option || 'domain',
            searchText: this.props.searchData ? this.props.searchData : '',
        };
    }

    render() {
        return (
            <SearchInput
                dark={!!this.props.isHeader}
                name='search'
                fluid={true}
                value={this.state.searchText}
                placeholder='Enter domain name'
                error={this.state.error}
                onChange={(event) =>
                    this.setState({
                        searchText: event.target.value,
                        error: false,
                    })
                }
                onKeyPress={(event) => {
                    if (event.key === 'Enter') {
                        if (this.state.searchText.length === 0) {
                            this.setState({
                                error: true,
                            });
                        } else {
                            this.props.router.push(
                                `/search/${
                                    this.state.selected
                                }/${this.state.searchText.trim()}`,
                                `/search/${
                                    this.state.selected
                                }/${this.state.searchText.trim()}`
                            );
                        }
                    }
                }}
            />
        );
    }
}
export default withRouter(Search);
