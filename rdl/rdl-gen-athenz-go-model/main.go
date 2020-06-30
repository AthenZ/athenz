// Copyright 2015 Yahoo Inc. https://github.com/ardielle
//           2019 Oath Holdings Inc. Modified to generate go client code for Athenz Clients
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"

	"github.com/ardielle/ardielle-go/rdl"
)

type clientGenerator struct {
	registry    rdl.TypeRegistry
	schema      *rdl.Schema
	name        string
	writer      *bufio.Writer
	err         error
	banner      string
	prefixEnums bool
	precise     bool
	ns          string
	librdl      string
}

const RdlGoImport = "github.com/ardielle/ardielle-go/rdl"

func main() {
	banner := "rdl (development version)"
	if rdl.Version != "" {
		banner = fmt.Sprintf("rdl %s", rdl.Version)
	}

	pOutdir := flag.String("o", ".", "Output directory")
	pBase := flag.String("b", "", "Base Path")
	pSchemaFile := flag.String("s", "", "RDL source file")
	flag.Parse()

	schema, err := rdl.ParseRDLFile(*pSchemaFile, false, false, false)
	if err == nil {
		generateGoModel(banner, schema, *pOutdir, "", *pBase)
		os.Exit(0)
	}
	fmt.Fprintf(os.Stderr, "*** %v\n", err)
	os.Exit(1)
}

func generateGoModel(banner string, schema *rdl.Schema, outdir string, ns string, base string) error {
	return GenerateAthenzGoModel(schema, &GeneratorParams{
                Outdir:         outdir,
                Banner:         banner,
		Namespace:      "",
                LibRdl:         RdlGoImport,
	        PrefixEnums:    false,
                PreciseTypes:   true,
		UntaggedUnions: []string{},
                GenerateSchema: true,
        })
}
