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

package main

import (
	"errors"
	"fmt"
	"os"
	"strings"

	"github.com/AthenZ/athenz/libs/go/sia/host/hostdoc"
	"github.com/jawher/mow.cli"
)

func main() {
	app := cli.App(os.Args[0], "hostdoc parser program")

	// Global Options
	docFile := app.String(cli.StringOpt{
		Name:  "f file",
		Value: "/var/lib/sia/host_document",
		Desc:  "path to the host document file",
	})

	app.Command("show", "show entries from host document", func(cmd *cli.Cmd) {
		var (
			domain  = cmd.BoolOpt("d domain", false, "show domain")
			service = cmd.BoolOpt("s service", false, "show services, comma separated")
			profile = cmd.BoolOpt("p profile", false, "show profile")
			primary = cmd.BoolOpt("primary-service", false, "show primary service")
		)

		cmd.Action = func() {
			result, err := Process(*docFile, *domain, *service, *profile, *primary)
			if err != nil {
				fmt.Fprintln(os.Stderr, err)
			} else {
				fmt.Printf("%s\n", result)
			}
		}
	})

	app.Run(os.Args)
}

func Process(docFile string, domain, service, profile, primary bool) (string, error) {
	b, err := os.ReadFile(docFile)
	if err != nil {
		return "", err
	}

	doc, _, err := hostdoc.NewPlainDoc(b)
	if err != nil {
		return "", err
	}

	// the first non-false flag wins the precedence
	switch {
	case domain:
		return doc.Domain, nil
	case service:
		return strings.Join(doc.Services, ","), nil
	case profile:
		return doc.Profile, nil
	case primary:
		return doc.Services[0], nil
	default:
		return "", errors.New("no selection made to print from host document")
	}
	return "", nil
}
