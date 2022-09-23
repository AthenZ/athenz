// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package main

import (
	"flag"
	"fmt"
	"os"

	"github.com/ardielle/ardielle-go/rdl"
)

func main() {
	banner := "rdl (development version)"
	if rdl.Version != "" {
		banner = fmt.Sprintf("rdl %s", rdl.Version)
	}

	pOutdir := flag.String("o", ".", "Output directory")
	pSchemaFile := flag.String("s", "", "RDL source file")
	pClassName := flag.String("c", "", "RDL Generated Class Name")

	flag.Parse()

	schema, err := rdl.ParseRDLFile(*pSchemaFile, false, false, false)
	if err == nil {
		generateJavaClient(banner, schema, *pOutdir, *pClassName)
		os.Exit(0)
	}
	fmt.Fprintf(os.Stderr, "*** %v\n", err)
	os.Exit(1)
}

func generateJavaClient(banner string, schema *rdl.Schema, outdir, className string) error {
	return GenerateAthenzJavaClient(schema, &GeneratorParams{
		Outdir:    outdir,
		Banner:    banner,
		Namespace: "",
		ClassName: className,
	})
}
