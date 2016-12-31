// Copyright 2016 Yahoo Inc.
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package zmscli

import (
	"github.com/boynton/repl"
)

func (cli *Zms) Eval(expr string) (string, bool, error) {
	if expr == "" {
		return "", false, nil
	}
	params, err := cli.tokenizer(expr)
	if err != nil {
		return "", false, err
	}
	result, err := cli.EvalCommand(params)
	if result == nil || err != nil {
		return "", false, err
	} else {
		return *result, false, err
	}
}

func (cli *Zms) Prompt() string {
	red := "\033[0;31m"
	black := "\033[0;0m"
	return red + cli.Domain + "> " + black
}

func (cli *Zms) Reset() {
}

func (cli *Zms) Complete(expr string) (string, []string) {
	return "", nil
}

func (cli *Zms) Start() []string {
	return nil
}

func (cli *Zms) Stop(history []string) {
}

func (cli *Zms) Repl() (*string, error) {
	repl.REPL(cli)
	return nil, nil
}
