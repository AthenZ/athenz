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
import NavBar from '../denali/NavBar';
import NavBarItem from '../denali/NavBarItem';
import { Link } from '../../routes';
import styled from '@emotion/styled';
import HeaderMenu from './HeaderMenu';
import Search from '../search/Search';

const Logo = ({ className }) => (
    <img src='/static/athenz-logo-full.png' className={className} />
);

const LogoStyled = styled(Logo)`
    height: 36px;
    cursor: pointer;
`;

const NavBarDiv = styled.div`
    height: 60px;
    position: relative;
`;

const NavBarItemDiv = styled.div`
    margin-left: 10%;
    width: 50%;
`;

export default (props) => {
    let search = '';
    if (props.showSearch) {
        search = <Search isHeader={true} searchData={props.searchData} />;
    }
    return (
        <NavBarDiv data-testid='header'>
            <NavBar background={'#002339'}>
                <NavBarItem>
                    <Link route='home'>
                        <a>
                            <LogoStyled />
                        </a>
                    </Link>
                </NavBarItem>
                <NavBarItemDiv>
                    <NavBarItem width='100%'>{search}</NavBarItem>
                </NavBarItemDiv>
                <NavBarItem right>
                    <HeaderMenu
                        headerDetails={props.headerDetails}
                        pending={props.pending}
                    />
                </NavBarItem>
            </NavBar>
        </NavBarDiv>
    );
};
