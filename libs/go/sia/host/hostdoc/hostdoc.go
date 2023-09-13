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

package hostdoc

import (
	"encoding/json"
	"fmt"
	"net"
	"os"
	"strings"
	"time"

	"github.com/AthenZ/athenz/libs/go/sia/host/hostdoc/raw"
	"github.com/AthenZ/athenz/libs/go/sia/host/provider"
)

const (
	DOMAIN              = "domain"
	SERVICE             = "service"
	SERVICES            = "services"
	PROFILE             = "profile"
	PROFILE_RESTRICT_TO = "profile_restrict_to"
	PROVIDER            = "provider"
	IP                  = "ip"
	UUID                = "uuid"
	ZONE                = "zone"
)

type Doc struct {
	Provider          provider.Provider
	Domain            string
	Profile           string
	ProfileRestrictTo string
	Services          []string
	AccountId         string
	ProjectNumber     string
	Uuid              string
	Ip                map[string]bool
	Zone              string
	Bytes             []byte
	LaunchTime        time.Time
}

// NewPlainDoc returns Doc, the provider string from the host_document, and an error
func NewPlainDoc(bytes []byte) (*Doc, string, error) {
	var d raw.Doc
	err := json.Unmarshal(bytes, &d)
	if err != nil {
		return nil, "", err
	}

	if d.Domain == "" {
		return nil, "", fmt.Errorf("unable to find %s in host_document, json: %v", DOMAIN, d)
	}

	svcs := d.Service
	if svcs == "" {
		if d.Services == "" {
			return nil, "", fmt.Errorf("unable to find %s or %s in host_document, json: %v", SERVICE, SERVICES, d)
		}
		svcs = d.Services
	}

	uuid := d.Uuid
	if uuid != "" && !strings.Contains(uuid, "-") && !strings.Contains(uuid, ".") {
		if len(uuid) == 32 {
			uuid = uuid[0:8] + "-" + uuid[8:12] + "-" + uuid[12:16] + "-" + uuid[16:20] + "-" + uuid[20:]
		}
	}

	// transform ips from an array of strings to a map for an easy lookup
	ip := map[string]bool{}
	for _, item := range d.Ip {
		parsedIp := net.ParseIP(strings.TrimSpace(item))
		if parsedIp != nil {
			ip[strings.ToLower(parsedIp.String())] = true
		}
	}

	return &Doc{
		Domain:            d.Domain,
		Services:          strings.Split(svcs, ","),
		Profile:           d.Profile,
		ProfileRestrictTo: d.ProfileRestrictTo,
		AccountId:         d.AccountId,
		ProjectNumber:     d.ProjectNumber,
		Uuid:              uuid,
		Zone:              d.Zone,
		Ip:                ip,
		Bytes:             bytes,
		LaunchTime:        d.LaunchTime,
	}, d.Provider, nil
}

func Write(doc raw.Doc, docPath string) error {
	docJsonBytes, err := json.Marshal(doc)
	if err != nil {
		return err
	}
	return os.WriteFile(docPath, docJsonBytes, 0644)
}
