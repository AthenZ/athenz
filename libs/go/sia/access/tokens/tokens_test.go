//
// Copyright The Athenz Authors
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//

package tokens

import (
	"crypto"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/json"
	"encoding/pem"
	"fmt"
	"github.com/AthenZ/athenz/clients/go/zts"
	"github.com/AthenZ/athenz/libs/go/sia/access/config"
	"github.com/dgrijalva/jwt-go"
	"github.com/dimfeld/httptreemux"
	"github.com/stretchr/testify/assert"
	"github.com/stretchr/testify/require"
	"io"
	"io/ioutil"
	"log"
	"math/big"
	"net"
	"net/http"
	"net/url"
	"os"
	"os/user"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

type AccessTokenClaims struct {
	Audience string   `json:"aud"`
	Scopes   []string `json:"scp"`
	jwt.StandardClaims
}

type testServer struct {
	listener net.Listener
	addr     string
}

func (t *testServer) start(h http.Handler) {
	listener, err := net.Listen("tcp", ":0")
	if err != nil {
		log.Panicln("Unable to serve on randomly assigned port")
	}
	s := &http.Server{Handler: h}
	t.listener = listener
	t.addr = listener.Addr().String()

	go func() {
		s.Serve(listener)
	}()
}

func (t *testServer) stop() {
	t.listener.Close()
}

func (t *testServer) baseUrl(version string) string {
	return "http://" + t.addr + "/" + version
}

func TestToBeRefreshed(t *testing.T) {
	tokenDir, err := ioutil.TempDir("", "tokens")
	require.Nilf(t, err, "should be able to create a temp directory")
	//defer os.RemoveAll(tokenDir)

	log.Printf("temp dir: %s", tokenDir)
	domain := "athenz.examples"
	service := "httpd"

	tokens := []config.AccessToken{
		// case 1: token doesn't exist
		config.AccessToken{
			FileName: "writer",
			Domain:   domain,
			Service:  service,
		},
		// case 2: token exists, and not expired
		config.AccessToken{
			FileName: "reader",
			Domain:   domain,
			Service:  service,
		},
		// case 3: token exists, and age is old
		config.AccessToken{
			FileName: "reader-aged",
			Domain:   domain,
			Service:  service,
		},
		// case 4: non readable token
		config.AccessToken{
			FileName: "reader-fail1",
			Domain:   domain,
			Service:  service,
		},
		// case 5: readable token, unmarshallable
		config.AccessToken{
			FileName: "reader-fail2",
			Domain:   domain,
			Service:  service,
		},
		// case 6: readable token, marshallable, no expires_in field
		config.AccessToken{
			FileName: "reader-fail3",
			Domain:   domain,
			Service:  service,
		},
	}

	domainDir := filepath.Join(tokenDir, domain)
	err = os.Mkdir(domainDir, 0755)
	require.Nilf(t, err, fmt.Sprintf("should be able to create directory: %s", domainDir))

	tpath := filepath.Join(tokenDir, domain, "reader")
	log.Printf("Creating a token at: %s", tpath)
	err = ioutil.WriteFile(tpath, token(3600), 0400)
	require.Nilf(t, err, fmt.Sprintf("should be able to create token: %s", tpath))

	tpath = filepath.Join(tokenDir, domain, "reader-aged")
	log.Printf("Creating a token at: %s", tpath)
	err = ioutil.WriteFile(tpath, token(3600), 0400)
	require.Nilf(t, err, fmt.Sprintf("should be able to create token: %s", tpath))
	err = os.Chtimes(tpath, time.Now(), time.Now().Add(-time.Minute*90))

	tpath = filepath.Join(tokenDir, domain, "reader-fail1")
	log.Printf("Creating a token at: %s", tpath)
	err = ioutil.WriteFile(tpath, []byte("{}"), 0000)
	require.Nilf(t, err, fmt.Sprintf("should be able to create token: %s", tpath))

	tpath = filepath.Join(tokenDir, domain, "reader-fail2")
	log.Printf("Creating a token at: %s", tpath)
	err = ioutil.WriteFile(tpath, []byte("asdf"), 0400)
	require.Nilf(t, err, fmt.Sprintf("should be able to create token: %s", tpath))

	tpath = filepath.Join(tokenDir, domain, "reader-fail3")
	log.Printf("Creating a token at: %s", tpath)
	err = ioutil.WriteFile(tpath, []byte(fmt.Sprintf("{%q: %q, %q: %q}", "access_token", "signed-string", "token_type", "Bearer")), 0400)
	require.Nilf(t, err, fmt.Sprintf("should be able to create token: %s", tpath))

	toRefresh, errors := ToBeRefreshed(tokenDir, tokens)
	assert.True(t, len(errors) == 3, fmt.Sprintf("there shoud be errors in fetching ToBeRefreshed tokend, err: %v", err))
	log.Printf("errors so far: %+v", errors)

	log.Printf("toRefresh: %#v", toRefresh)
	assert.NotNil(t, toRefresh, "list of tokens to be refreshed should not be empty")
	assert.True(t, len(toRefresh) == 2, "there should be one token to be refreshed")
	assert.Equalf(t, toRefresh[0].FileName, "writer", fmt.Sprintf("first item: %+v should be %q", toRefresh[0], "writer"))
	assert.Equalf(t, toRefresh[1].FileName, "reader-aged", fmt.Sprintf("second item: %+v should be %q", toRefresh[0], "reader-aged"))
}

func TestTokenDirs(t *testing.T) {
	cases := []struct {
		Name     string
		Root     string
		Tokens   []config.AccessToken
		Expected []string
	}{
		{"Empty List", "/tmp", []config.AccessToken{}, []string{}},
		{"Base line",
			"/tmp",
			[]config.AccessToken{
				config.AccessToken{Domain: "media.ops"},
				config.AccessToken{Domain: "movies.ops"},
			},
			[]string{"/tmp/media.ops", "/tmp/movies.ops"},
		},
		{"Empty root", "", []config.AccessToken{config.AccessToken{Domain: "media.ops"}}, []string{"media.ops"}},
	}

	for _, tc := range cases {
		t.Run(tc.Name, func(t *testing.T) {
			actual := TokenDirs(tc.Root, tc.Tokens)
			assert.Equal(t, actual, tc.Expected)
		})
	}
}

// TestAccessTokensSuccess verifies that access tokens are not refreshed on subsequent retry if age of the token is not oldenough
func TestAccessTokensSuccess(t *testing.T) {
	siaDir, err := ioutil.TempDir("", "sia.")
	require.Nil(t, err, "should be able to create temp folder for sia")
	//defer os.RemoveAll(hcaDir)

	// Mock ZTS AccessTokens api
	ztsRouter := httptreemux.New()
	eckey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Mock Access Tokens
	ztsRouter.POST("/zts/v1/oauth2/token", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Printf("Called /zts/v1/instance")
		io.WriteString(w, makeAccessToken(r, eckey))
	})

	ztsServer := &testServer{}
	ztsServer.start(ztsRouter)
	defer ztsServer.stop()

	opts := &config.TokenOptions{
		Domain:   "iaas.athens",
		Services: []string{"httpd", "yamas"},
		CertDir:  filepath.Join(siaDir, "certs"),
		KeyDir:   filepath.Join(siaDir, "keys"),
		TokenDir: filepath.Join(siaDir, "tokens"),
		Tokens: []config.AccessToken{
			config.AccessToken{FileName: "token1", Service: "httpd", Domain: "athenz.demo", Roles: []string{"role1"}, User: username(t), Uid: uid(t), Gid: gid(t), Expiry: 7200},
			config.AccessToken{FileName: "token2", Service: "httpd", Domain: "athenz.demo", Roles: []string{"role1", "role2"}, User: username(t), Uid: uid(t), Gid: gid(t), Expiry: 7200},
			config.AccessToken{FileName: "token3", Service: "httpd", Domain: "athenz.demo", Roles: []string{"*"}, User: username(t), Uid: uid(t), Gid: gid(t), Expiry: 7200},
			config.AccessToken{FileName: "token4", Service: "httpd", Domain: "athenz.demo", Roles: []string{"token4"}, User: username(t), Uid: uid(t), Gid: gid(t), Expiry: 7200},
			config.AccessToken{FileName: "token1", Service: "httpd", Domain: "athenz.examples", Roles: []string{"token1"}, User: username(t), Uid: uid(t), Gid: gid(t), Expiry: 7200},
		},
		ZtsUrl: ztsServer.baseUrl("zts/v1"),
	}

	log.Printf("Options fed are: %+v", opts)

	makeSiaDirs(t, opts)
	makeIdentity(t, opts)

	// 1) Normal Fetch Tokens
	errs := Fetch(opts)
	assert.Lenf(t, errs, 0, "should be able to create access tokens, errs: %v", err)
	assertAccessTokens(t, opts)

	// 2) Write token errors
	// Set old time stamp on a token
	tpath := filepath.Join(opts.TokenDir, "athenz.demo", "token1")
	err = os.Chtimes(tpath, time.Now(), time.Now().Add(-90*time.Minute))
	assert.NoErrorf(t, err, "unable to change time on: %s, err: %v", tpath, err)

	// Set incorrect owner ship
	dpath := filepath.Join(opts.TokenDir, "athenz.demo")
	err = os.Chmod(dpath, 0500)
	assert.NoErrorf(t, err, "should be able to change permissions on: %s, err: %v", dpath, err)

	errs = Fetch(opts)
	assert.Lenf(t, errs, 1, "should be one error related to token1, errs: %v", err)
	log.Printf("errors; %+v", errs)
}

// TestAccessTokensRerun verifies that access tokens are being fetched
func TestAccessTokensRerun(t *testing.T) {
	siaDir, err := ioutil.TempDir("", "sia.")
	require.Nil(t, err, "should be able to create temp folder for sia")
	//defer os.RemoveAll(hcaDir)

	// Mock ZTS AccessTokens api
	ztsRouter := httptreemux.New()
	eckey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Mock Access Tokens
	ztsRouter.POST("/zts/v1/oauth2/token", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Printf("Called /zts/v1/instance")
		io.WriteString(w, makeAccessToken(r, eckey))
	})

	ztsServer := &testServer{}
	ztsServer.start(ztsRouter)
	defer ztsServer.stop()

	opts := &config.TokenOptions{
		Domain:   "iaas.athens",
		Services: []string{"httpd", "yamas"},
		CertDir:  filepath.Join(siaDir, "certs"),
		KeyDir:   filepath.Join(siaDir, "keys"),
		TokenDir: filepath.Join(siaDir, "tokens"),
		Tokens: []config.AccessToken{
			config.AccessToken{FileName: "token1", Service: "httpd", Domain: "athenz.demo", Roles: []string{"role1"}, User: username(t), Uid: uid(t), Gid: gid(t), Expiry: 7200},
		},
		ZtsUrl: ztsServer.baseUrl("zts/v1"),
	}

	log.Printf("Options fed are: %+v", opts)

	makeSiaDirs(t, opts)
	makeIdentity(t, opts)

	// 1) Normal Fetch Tokens
	errs := Fetch(opts)
	assert.Lenf(t, errs, 0, "should be able to create access tokens, errs: %v", err)
	assertAccessTokens(t, opts)

	// Note the time stamp in 'before'
	tpath := filepath.Join(opts.TokenDir, opts.Tokens[0].Domain, opts.Tokens[0].FileName)
	before, err := os.Stat(tpath)
	assert.NoErrorf(t, err, "unable to stat, err: %v", err)

	time.Sleep(1 * time.Second)

	// Fetch tokens, after 1 second, this should result in no real execution
	errs = Fetch(opts)
	assert.Lenf(t, errs, 0, "should be able to create access tokens, errs: %v", err)
	assertAccessTokens(t, opts)

	// Verify the time stamp on the token
	after, err := os.Stat(tpath)
	assert.NoErrorf(t, err, "unable to stat, err: %v", err)
	assert.Equalf(t, after.ModTime(), before.ModTime(), "before: %v, after: %v should be same", before, after)

	// Sequence 2: Force an older time stamp, and then attempt a rerun, and the token should be refreshed
	err = os.Chtimes(tpath, time.Now(), time.Now().Add(-90*time.Minute))
	assert.NoErrorf(t, err, "unable to change time, err: %v", err)

	before, err = os.Stat(tpath)
	assert.NoErrorf(t, err, "unable to stat, err: %v", err)

	errs = Fetch(opts)
	assert.Lenf(t, errs, 0, "should be able to create access tokens, errs: %v", err)
	assertAccessTokens(t, opts)

	after, err = os.Stat(tpath)
	assert.NoErrorf(t, err, "unable to stat, err: %v", err)
	assert.NotEqualf(t, after.ModTime(), before.ModTime(), "before: %v, after: %v should be different", before, after)
}

// TestAccessTokensUserAgent verifies that user agent is set in client calls
func TestAccessTokensUserAgent(t *testing.T) {
	siaDir, err := ioutil.TempDir("", "sia.")
	require.Nil(t, err, "should be able to create temp folder for sia")
	//defer os.RemoveAll(hcaDir)

	userAgent := "tokencli-1.0.0 colo-a"

	// Mock ZTS AccessTokens api
	ztsRouter := httptreemux.New()
	eckey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Mock Access Tokens
	ztsRouter.POST("/zts/v1/oauth2/token", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Printf("Called /zts/v1/instance")
		if r.Header.Get(USER_AGENT) != userAgent {
			panic("User-Agent is not set")
		}
		io.WriteString(w, makeAccessToken(r, eckey))
	})

	ztsServer := &testServer{}
	ztsServer.start(ztsRouter)
	defer ztsServer.stop()

	opts := &config.TokenOptions{
		Domain:   "iaas.athens",
		Services: []string{"httpd", "yamas"},
		CertDir:  filepath.Join(siaDir, "certs"),
		KeyDir:   filepath.Join(siaDir, "keys"),
		TokenDir: filepath.Join(siaDir, "tokens"),
		Tokens: []config.AccessToken{
			config.AccessToken{FileName: "token1", Service: "httpd", Domain: "athenz.demo", Roles: []string{"role1"}, User: username(t), Uid: uid(t), Gid: gid(t), Expiry: 7200},
		},
		ZtsUrl:    ztsServer.baseUrl("zts/v1"),
		UserAgent: userAgent,
	}

	log.Printf("Options fed are: %+v", opts)

	makeSiaDirs(t, opts)
	makeIdentity(t, opts)

	// Normal Fetch Tokens
	errs := Fetch(opts)
	assert.Lenf(t, errs, 0, "should be able to create access tokens, errs: %v", err)
	assertAccessTokens(t, opts)
}

// TestAccessTokensMixedTokenErrors verifies that access tokens fetchable for the good tokens
func TestAccessTokensMixedTokenErrors(t *testing.T) {
	siaDir, err := ioutil.TempDir("", "sia.")
	require.Nil(t, err, "should be able to create temp folder for sia")
	//defer os.RemoveAll(hcaDir)

	// Mock ZTS AccessTokens api
	ztsRouter := httptreemux.New()
	eckey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Mock Access Tokens
	ztsRouter.POST("/zts/v1/oauth2/token", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Printf("Called /zts/v1/instance")
		io.WriteString(w, makeAccessToken(r, eckey))
	})

	ztsServer := &testServer{}
	ztsServer.start(ztsRouter)
	defer ztsServer.stop()

	opts := &config.TokenOptions{
		Domain:   "iaas.athens",
		Services: []string{"httpd", "yamas"},
		CertDir:  filepath.Join(siaDir, "certs"),
		KeyDir:   filepath.Join(siaDir, "keys"),
		TokenDir: filepath.Join(siaDir, "tokens"),
		Tokens: []config.AccessToken{
			config.AccessToken{FileName: "token1", Service: "httpd", Domain: "athenz.demo", Roles: []string{"role1"}, User: username(t), Uid: uid(t), Gid: gid(t), Expiry: 7200},
			config.AccessToken{FileName: "token2", Service: "httpd", Domain: "athenz.demo", Roles: []string{"role1"}, User: username(t), Uid: uid(t), Gid: gid(t), Expiry: 7200},
		},
		ZtsUrl: ztsServer.baseUrl("zts/v1"),
	}

	log.Printf("Options fed are: %+v", opts)

	makeSiaDirs(t, opts)
	makeIdentity(t, opts)

	// Fetch tokens, there should be no errors here
	errs := Fetch(opts)
	assert.Lenf(t, errs, 0, "should be able to create access tokens, errs: %v", err)
	assertAccessTokens(t, opts)

	// Force an older time stamp on token1
	tpath := filepath.Join(opts.TokenDir, opts.Tokens[0].Domain, opts.Tokens[0].FileName)
	err = os.Chtimes(tpath, time.Now(), time.Now().Add(-90*time.Minute))
	assert.NoErrorf(t, err, "unable to change time, err: %v", err)

	// Force a bad token at token2
	tpath = filepath.Join(opts.TokenDir, "athenz.demo", "token2")
	err = os.Chmod(tpath, 0000)
	require.Nilf(t, err, fmt.Sprintf("should be able to modify token2: %s", tpath))

	errs = Fetch(opts)
	assert.Lenf(t, errs, 1, "should be one error related to token2, err: %v", errs)
	log.Printf("tokens error: %v", errs)

	// Make sure token1 is updated
	tpath = filepath.Join(opts.TokenDir, "athenz.demo", "token1")
	f, err := os.Stat(tpath)
	assert.NoErrorf(t, err, "should be able to stat file: %s, err: %v", tpath, err)
	assert.True(t, time.Now().Add(-1*time.Minute).Before(f.ModTime()), "token1 should be updated, and should have modified time closer to now, modified time: %v", f.ModTime())
}

// TestAccessTokensApiErrors verifies that ZTS api errors are handled correctly
func TestAccessTokensApiErrors(t *testing.T) {
	siaDir, err := ioutil.TempDir("", "sia.")
	require.Nil(t, err, "should be able to create temp folder for sia")
	//defer os.RemoveAll(hcaDir)

	// Mock ZTS AccessTokens api
	ztsRouter := httptreemux.New()
	eckey, _ := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)

	// Mock Access Tokens
	c := 0
	ztsRouter.POST("/zts/v1/oauth2/token", func(w http.ResponseWriter, r *http.Request, params map[string]string) {
		log.Printf("Called /zts/v1/token")
		// Success the first time, api error second time, json error the third time
		switch c {
		case 0:
			io.WriteString(w, makeAccessToken(r, eckey))
		case 2:
			io.WriteString(w, "bad response content")
		case 1:
		default:
			w.WriteHeader(http.StatusInternalServerError)
			io.WriteString(w, string("{}"))
		}
		c = c + 1
	})

	ztsServer := &testServer{}
	ztsServer.start(ztsRouter)
	defer ztsServer.stop()

	opts := &config.TokenOptions{
		Domain:   "iaas.athens",
		Services: []string{"httpd", "yamas"},
		CertDir:  filepath.Join(siaDir, "certs"),
		KeyDir:   filepath.Join(siaDir, "keys"),
		TokenDir: filepath.Join(siaDir, "tokens"),
		Tokens: []config.AccessToken{
			config.AccessToken{FileName: "token1", Service: "httpd", Domain: "athenz.demo", Roles: []string{"role1"}, User: username(t), Uid: uid(t), Gid: gid(t), Expiry: 7200},
		},
		ZtsUrl: ztsServer.baseUrl("zts/v1"),
	}

	log.Printf("Options fed are: %+v", opts)

	makeSiaDirs(t, opts)
	makeIdentity(t, opts)

	// Fetch tokens, there should be no errors here
	errs := Fetch(opts)
	assert.Lenf(t, errs, 0, "should be able to create access tokens, errs: %v", err)
	assertAccessTokens(t, opts)

	// Handling ZTS 500s
	tpath := filepath.Join(opts.TokenDir, opts.Tokens[0].Domain, opts.Tokens[0].FileName)
	err = os.Chtimes(tpath, time.Now(), time.Now().Add(-90*time.Minute))
	assert.NoErrorf(t, err, "unable to change time, err: %v", err)
	before, err := os.Stat(tpath)
	assert.NoErrorf(t, err, "should be able to stat file: %s, err: %v", tpath, err)

	errs = Fetch(opts)
	assert.Lenf(t, errs, 1, "should be one error related to token1, err: %v", errs)
	log.Printf("tokens error: %v", err)

	// Make sure token1 is not updated, since ZTS is giving an api error
	after, err := os.Stat(tpath)
	assert.NoErrorf(t, err, "should be able to stat file: %s, err: %v", tpath, err)
	assert.Equalf(t, before.ModTime(), after.ModTime(), "token1 should not be updated when ZTS gives an error, before: %v, after: %v", before, after)

	// Handling ZTS returning bad content
	errs = Fetch(opts)
	assert.Lenf(t, errs, 1, "should be one error related to token1, err: %v", errs)
	log.Printf("tokens error: %v", err)

	// Make sure token1 is not updated, since ZTS is giving an api error
	after, err = os.Stat(tpath)
	assert.NoErrorf(t, err, "should be able to stat file: %s, err: %v", tpath, err)
	assert.Equalf(t, before.ModTime(), after.ModTime(), "token1 should not be updated when ZTS gives an error, before: %v, after: %v", before, after)
}

// TestAccessTokensEmpty verifies that no execution is done if no access tokens are configured
func TestAccessTokensEmpty(t *testing.T) {
	errs := Fetch(&config.TokenOptions{})
	assert.Lenf(t, errs, 0, "when there are not access tokens, there should be no error, err: %v", errs)
}

// TestAccessTokensBadCerts verifies that an error is returned when no certs are found
func TestAccessTokensBadCerts(t *testing.T) {
	siaDir, err := ioutil.TempDir("", "sia.")
	require.Nil(t, err, "should be able to create temp folder for sia")
	//defer os.RemoveAll(hcaDir)

	opts := &config.TokenOptions{
		Domain:   "iaas.athens",
		Services: []string{"httpd", "yamas"},
		CertDir:  filepath.Join(siaDir, "certs"),
		KeyDir:   filepath.Join(siaDir, "keys"),
		TokenDir: filepath.Join(siaDir, "tokens"),
		Tokens: []config.AccessToken{
			config.AccessToken{FileName: "token1", Service: "httpd", Domain: "athenz.demo", Roles: []string{"role1"}, User: username(t), Uid: uid(t), Gid: gid(t), Expiry: 7200},
		},
		ZtsUrl: "http://testurl.invalid",
	}

	log.Printf("Options fed are: %+v", opts)

	makeSiaDirs(t, opts)

	// Fetch Tokens should return errors, since identity svc certs are not present
	errs := Fetch(opts)
	assert.Lenf(t, errs, 3, "there should be 2 errors, errs: %+v", errs)
	log.Printf("Errors: %+v", errs)
}

func token(expiry int) []byte {
	expiry32 := int32(expiry)
	tokenResponse := zts.AccessTokenResponse{
		Access_token: "signed string",
		Expires_in:   &expiry32,
		Token_type:   "Bearer",
	}

	bytes, err := json.Marshal(tokenResponse)
	if err != nil {
		panic(err)
	}

	return bytes
}

func makeSiaDirs(t *testing.T, opts *config.TokenOptions) {
	dirs := []string{opts.CertDir, opts.KeyDir, opts.TokenDir}
	dirs = append(dirs, TokenDirs(opts.TokenDir, opts.Tokens)...)
	for _, d := range dirs {
		if e := os.MkdirAll(d, 0755); e != nil {
			log.Printf("unable to create folder: %s, err: %v", d, e)
			t.FailNow()
		}
	}
}

func makeAccessToken(r *http.Request, key crypto.PrivateKey) string {
	audScopes := func(scope string) (string, []string) {
		tokens := strings.Split(scope, " ")
		if len(tokens) == 0 {
			panic(fmt.Errorf("invalid scope passed, no tokens: %q", scope))
		}

		// process the first token in the scope
		parts := strings.Split(tokens[0], ":role.")
		if len(parts) == 0 {
			panic(fmt.Errorf("invalid scope passed, non empty scope needed: %q", scope))
		}

		domain := parts[0]
		roles := []string{}

		if len(parts) == 1 {
			// only domain specified, mint some roles
			roles = append(roles, []string{"role1", "role2", "role3"}...)
		} else {
			roles = append(roles, parts[1])
		}

		// process remaining parts of the scope
		for _, token := range tokens[1:] {
			parts := strings.Split(token, ":role.")
			if len(parts) == 1 {
				panic(fmt.Errorf("invalid scope passed, remaining tokens need to roles: %q", scope))
			} else {
				roles = append(roles, parts[1])
			}
		}
		return domain, roles
	}

	body, err := ioutil.ReadAll(r.Body)
	if err != nil {
		panic(err)
	}

	log.Printf("Body: %q", string(body))
	values, err := url.ParseQuery(string(body))
	if err != nil {
		panic(err)
	}

	log.Printf("Scopes: %+v", values.Get("scope"))
	audience, roles := audScopes(values.Get("scope"))

	expiry, err := strconv.Atoi(values.Get("expires_in"))
	if err != nil {
		panic(err)
	}

	claims := &AccessTokenClaims{
		Audience: audience,
		Scopes:   roles,
		StandardClaims: jwt.StandardClaims{
			ExpiresAt: time.Now().Add(time.Duration(expiry) * time.Second).Unix(),
			Issuer:    "athenz",
			Subject:   "principal.test",
			IssuedAt:  time.Now().Unix(),
		},
	}

	token := jwt.NewWithClaims(jwt.SigningMethodES256, claims)

	signedToken, err := token.SignedString(key)
	if err != nil {
		panic(err)
	}

	expiry32 := int32(expiry)
	tokenResponse := zts.AccessTokenResponse{
		Access_token: signedToken,
		Expires_in:   &expiry32,
		Token_type:   "Bearer",
	}

	bytes, err := json.Marshal(tokenResponse)
	if err != nil {
		panic(err)
	}

	return string(bytes)
}

// makeIdentity creates self-signed cert/key for each service provided
func makeIdentity(t *testing.T, opts *config.TokenOptions) {
	for _, svc := range opts.Services {
		svcKey, err := rsa.GenerateKey(rand.Reader, 2048)
		if err != nil {
			t.Fatalf("unable to create a key, err: %v", err)
		}

		notBefore := time.Now().Add(-1 * time.Hour)
		notAfter := time.Now().Add(1 * time.Hour)

		serialNumberLimit := new(big.Int).Lsh(big.NewInt(1), 128)
		serialNumber, err := rand.Int(rand.Reader, serialNumberLimit)
		if err != nil {
			t.Fatalf("failed to generate serial number: %v", err)
		}

		template := x509.Certificate{
			SerialNumber: serialNumber,
			Subject: pkix.Name{
				Organization: []string{"Acme Co"},
			},
			NotBefore: notBefore,
			NotAfter:  notAfter,

			KeyUsage:              x509.KeyUsageKeyEncipherment | x509.KeyUsageDigitalSignature,
			ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
			BasicConstraintsValid: true,
		}

		derBytes, err := x509.CreateCertificate(rand.Reader, &template, &template, &svcKey.PublicKey, svcKey)
		if err != nil {
			t.Fatalf("Failed to create certificate: %v", err)
		}

		certOut, err := os.Create(filepath.Join(opts.CertDir, fmt.Sprintf("%s.%s.cert.pem", opts.Domain, svc)))
		if err != nil {
			t.Fatalf("Failed to open cert.pem for writing: %v", err)
		}
		if err := pem.Encode(certOut, &pem.Block{Type: "CERTIFICATE", Bytes: derBytes}); err != nil {
			t.Fatalf("Failed to write data to cert.pem: %v", err)
		}
		if err := certOut.Close(); err != nil {
			t.Fatalf("Error closing cert.pem: %v", err)
		}

		keyOut, err := os.OpenFile(filepath.Join(opts.KeyDir, fmt.Sprintf("%s.%s.key.pem", opts.Domain, svc)), os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0600)
		if err != nil {
			t.Fatalf("Failed to open key.pem for writing: %v", err)
		}
		privBytes, err := x509.MarshalPKCS8PrivateKey(svcKey)
		if err != nil {
			t.Fatalf("Unable to marshal private key: %v", err)
		}
		if err := pem.Encode(keyOut, &pem.Block{Type: "PRIVATE KEY", Bytes: privBytes}); err != nil {
			t.Fatalf("Failed to write data to key.pem: %v", err)
		}
		if err := keyOut.Close(); err != nil {
			t.Fatalf("Error closing key.pem: %v", err)
		}
	}
}

// assertAccessTokens verifies the token files as per the information in options.AccessTokens
func assertAccessTokens(t *testing.T, opts *config.TokenOptions) {
	a := assert.New(t)

	for _, t := range opts.Tokens {
		fname := filepath.Join(opts.TokenDir, t.Domain, t.FileName)
		f, err := os.Stat(fname)
		a.Nil(err)

		a.Equal(os.FileMode(0440), f.Mode())

		if statt, ok := f.Sys().(*syscall.Stat_t); ok {
			a.Equal(statt.Uid, uint32(t.Uid))
			a.Equal(statt.Gid, uint32(t.Gid))
		}

		// Todo: parse the token and verify the scopes and expiry
		bytes, err := ioutil.ReadFile(fname)
		a.Nilf(err, "should be able to read the file, %q", fname)

		token := zts.AccessTokenResponse{}
		err = json.Unmarshal(bytes, &token)
		a.Nilf(err, "should be able to parse the token bytes into AccessTokenResponse type, bytes: %q", string(bytes))

		a.Equal(int32(t.Expiry), *token.Expires_in)
	}
}

// uid returns current user's uid
func uid(t *testing.T) int {
	u, err := user.Current()
	if err != nil {
		t.Fatalf("unable to get current user, err: %v", err)
	}
	id, err := strconv.Atoi(u.Uid)
	if err != nil {
		t.Fatalf("unexpected uid: %s, err: %v", u.Uid, err)
	}
	return id
}

// username returns current user's name
func username(t *testing.T) string {
	u, err := user.Current()
	if err != nil {
		t.Fatalf("unable to get current user, err: %v", err)
	}
	return u.Name
}

// gid returns current user's gid
func gid(t *testing.T) int {
	u, err := user.Current()
	if err != nil {
		t.Fatalf("unable to get current user, err: %v", err)
	}
	g, err := user.LookupGroupId(u.Gid)
	if err != nil {
		t.Fatalf("unable to get current group, err: %v", err)
	}
	id, err := strconv.Atoi(g.Gid)
	if err != nil {
		t.Fatalf("unexpected uid: %s, err: %v", g.Gid, err)
	}
	return id
}
