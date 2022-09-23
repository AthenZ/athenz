// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"github.com/AthenZ/athenz/clients/go/zms"
)

func (cli Zms) GetStats(dn string) (*string, error) {
	var stats *zms.Stats
	var err error
	if dn == "" {
		stats, err = cli.Zms.GetSystemStats()
	} else {
		stats, err = cli.Zms.GetStats(zms.DomainName(dn))
	}
	if err != nil {
		return nil, err
	}

	if cli.OutputFormat == DefaultOutputFormat {
		cli.OutputFormat = YAMLOutputFormat
	}

	return cli.dumpByFormat(stats, nil)
}
