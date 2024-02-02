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
import NavBar from '../denali/NavBar';
import NavBarItem from '../denali/NavBarItem';
import styled from '@emotion/styled';
import HeaderMenu from './HeaderMenu';
import Search from '../search/Search';
import Link from 'next/link';
import PageUtils from '../utils/PageUtils';

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

const Header = (props) => {
    let search = '';
    if (props.showSearch) {
        search = <Search isHeader={true} searchData={props.searchData} />;
    }
    return (
        <NavBarDiv data-testid='header'>
            <NavBar background={'#002339'}>
                <NavBarItem>
                    <Link href={PageUtils.homePage()}>
                        <LogoStyled />
                    </Link>
                </NavBarItem>
                <NavBarItemDiv>
                    <NavBarItem width='100%'>{search}</NavBarItem>
                </NavBarItemDiv>
                <NavBarItem right>
                    <HeaderMenu />
                </NavBarItem>
            </NavBar>
        </NavBarDiv>
    );
};

export default Header;
