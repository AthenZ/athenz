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

package sia

import (
	"crypto/rand"
	"crypto/rsa"
	"github.com/gorilla/mux"
	"github.com/stretchr/testify/assert"
	"os"
	"strings"
	"testing"
)

func TestGetOIDCToken(t *testing.T) {

	validToken := "eyJraWQiOiJmNGI4MjE4MzdiNGVkY2JhNTYxMzZmMjJmMzdlZTY5Njk1MjBkZjIzNDA3MTI2Y2NlMTg4ZDQxNDFjMDE1ZDY4IiwiYWxnIjoiUlMyNTYifQ.eyJpc3MiOiJodHRwczovL2FnZW50LmJ1aWxka2l0ZS5jb20iLCJzdWIiOiJvcmdhbml6YXRpb246dmVzcGFhaTpwaXBlbGluZTp2ZXNwYS1lbmdpbmUtdmVzcGEtam9ubXYtdGVzdDpyZWY6cmVmcy9oZWFkcy9tYXN0ZXI6Y29tbWl0OkhFQUQ6c3RlcDpwaXBlbGluZS10ZXN0IiwiYXVkIjoiaHR0cHM6Ly96dHMuYXRoZW56LmNkLnZlc3BhLWNsb3VkLmNvbTo0NDQzL3p0cy92MSIsImlhdCI6MTcyNDE1ODM4NCwibmJmIjoxNzI0MTU4Mzg0LCJleHAiOjE3MjQxNTg2ODQsIm9yZ2FuaXphdGlvbl9zbHVnIjoidmVzcGFhaSIsInBpcGVsaW5lX3NsdWciOiJ2ZXNwYS1lbmdpbmUtdmVzcGEtam9ubXYtdGVzdCIsImJ1aWxkX251bWJlciI6OSwiYnVpbGRfYnJhbmNoIjoibWFzdGVyIiwiYnVpbGRfY29tbWl0IjoiSEVBRCIsInN0ZXBfa2V5IjoicGlwZWxpbmUtdGVzdCIsImpvYl9pZCI6IjAxOTE2ZmQ4LWVlZWQtNDZhYS04MzA2LWI4YmY3YmI1MmE5MyIsImFnZW50X2lkIjoiMDE5MTZmZDktMDliMC00NDc4LTkzZWMtY2VlZmYyMDk3YTg1In0.c3TR_zGyG4Hjchk79q1CZBhNv56ahcxVOuHEpfUwD_HwYM7wdhm8XrtYnlKoMi8aBpirmGgBGqxtmswxz8YaVMDCf7OTI1S1SNRWNSuDYkjjWfKdXoAVTlV5yV6isgL-cb_hfDOv1Y-sWUvsG2_rtLTdqLDxtb5uxO6DqFPO8-fMqPsaWl3KygpAT7zo42szYncb0JOZe80ZADMWomp-ZnWTyZnNILfdxgyUb0KTbJWZva29F7vEMxhTPRgx2MMD3uqLv2xaMQlUF6hkX_mM8VyEZ_nBcKdw2kF9S77VSpAkICtbFdPaFTGI4QZJaBVQxbrVlrbAmwVt5p-DI_i-XQ"

	claims, err := GetOIDCTokenClaims(validToken)
	assert.Nil(t, err)

	assert.Equal(t, "vespa-engine-vespa-jonmv-test", claims["pipeline_slug"].(string))
	assert.Equal(t, "vespaai", claims["organization_slug"].(string))
	assert.Equal(t, 9, claims["build_number"].(string))
	assert.Equal(t, "01916fd8-eeed-46aa-8306-b8bf7bb52a93", claims["job_id"].(string))

	subjectParts := strings.Split(claims["sub"].(string), ":")
	assert.Equal(t, "orgainzation", subjectParts[0])
	assert.Equal(t, "vespaai", subjectParts[1])
	assert.Equal(t, "pipeline", subjectParts[2])
	assert.Equal(t, "vespa-engine-vespa-jonmv-test", subjectParts[3])
	assert.Equal(t, "ref", subjectParts[4])
	assert.Equal(t, "refs/heads/master", subjectParts[5])

	os.Clearenv()
}

func TestGetOIDCTokenInvalidToken(t *testing.T) {

	_, err := GetOIDCTokenClaims("invalid-token")
	assert.NotNil(t, err)
	assert.Equal(t, "unable to parse oidc token: go-jose/go-jose: compact JWS format must have three parts", err.Error())

	os.Clearenv()
}

func TestGetCSRDetails(t *testing.T) {

	privateKey, _ := rsa.GenerateKey(rand.Reader, 2048)
	csr, err := GetCSRDetails(privateKey, "sports", "api", "sys.auth.build-kite", "0001", "athenz.io", "athenz", "", "", "")
	assert.Nil(t, err)
	assert.True(t, csr != "")
}
