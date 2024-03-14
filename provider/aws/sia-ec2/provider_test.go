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
	"testing"

	"github.com/stretchr/testify/assert"
)

func TestEC2Provider_GetAdditionalSshHostPrincipals(t *testing.T) {
	provider := EC2Provider{
		SSHCertPublicIP: true,
	}
	sshPrincipal, err := provider.GetAdditionalSshHostPrincipals("http://127.0.0.1:5080")
	assert.Nil(t, err)
	assert.Equal(t, "i-03d1ae7035f931a90,172.31.30.75", sshPrincipal)

	provider = EC2Provider{
		SSHCertPublicIP: false,
	}
	sshPrincipal, err = provider.GetAdditionalSshHostPrincipals("http://127.0.0.1:5080")
	assert.Nil(t, err)
	assert.Equal(t, "i-03d1ae7035f931a90", sshPrincipal)

	provider = EC2Provider{}
	sshPrincipal, err = provider.GetAdditionalSshHostPrincipals("http://127.0.0.1:5080")
	assert.Nil(t, err)
	assert.Equal(t, "i-03d1ae7035f931a90", sshPrincipal)
}
