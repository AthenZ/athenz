// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.
// Original code based out of https://github.com/ardielle

package main

import (
	"bufio"
	"bytes"
	"os"
	"path/filepath"
	"strings"

	"github.com/ardielle/ardielle-go/rdl"
)

func formatBlock(s string, leftCol int, prefix string) string {
	if s == "" {
		return ""
	}
	tab := spaces(leftCol)
	var buf bytes.Buffer
	max := 80
	col := leftCol
	lines := 1
	tokens := strings.Split(s, " ")
	for _, tok := range tokens {
		toklen := len(tok)
		if col+toklen >= max {
			buf.WriteString("\n")
			lines++
			buf.WriteString(tab)
			buf.WriteString(prefix)
			buf.WriteString(tok)
			col = leftCol + 3 + toklen
		} else {
			if col == leftCol {
				col += len(prefix)
				buf.WriteString(prefix)
			} else {
				buf.WriteString(" ")
			}
			buf.WriteString(tok)
			col += toklen + 1
		}
	}
	buf.WriteString("\n")
	emptyPrefix := strings.Trim(prefix, " ")
	pad := tab + emptyPrefix + "\n"
	return pad + buf.String() + pad
}

func formatComment(s string, leftCol int) string {
	return formatBlock(s, leftCol, "// ")
}

func spaces(count int) string {
	return stringOfChar(count, ' ')
}

func stringOfChar(count int, b byte) string {
	buf := make([]byte, 0, count)
	for i := 0; i < count; i++ {
		buf = append(buf, b)
	}
	return string(buf)
}

func addFields(reg rdl.TypeRegistry, dst []*rdl.StructFieldDef, t *rdl.Type) []*rdl.StructFieldDef {
	switch t.Variant {
	case rdl.TypeVariantStructTypeDef:
		st := t.StructTypeDef
		if st.Type != "Struct" {
			dst = addFields(reg, dst, reg.FindType(st.Type))
		}
		for _, f := range st.Fields {
			dst = append(dst, f)
		}
	}
	return dst
}

func flattenedFields(reg rdl.TypeRegistry, t *rdl.Type) []*rdl.StructFieldDef {
	return addFields(reg, make([]*rdl.StructFieldDef, 0), t)
}

func capitalize(text string) string {
	return strings.ToUpper(text[0:1]) + text[1:]
}

func uncapitalize(text string) string {
	return strings.ToLower(text[0:1]) + text[1:]
}

func outputWriter(outdir string, name string, ext string) (*bufio.Writer, *os.File, string, error) {
	sname := "anonymous"
	if strings.HasSuffix(outdir, ext) {
		name = filepath.Base(outdir)
		sname = name[:len(name)-len(ext)]
		outdir = filepath.Dir(outdir)
	}
	if name != "" {
		sname = name
	}
	if outdir == "" {
		return bufio.NewWriter(os.Stdout), nil, sname, nil
	}
	outfile := sname
	if !strings.HasSuffix(outfile, ext) {
		outfile += ext
	}
	path := filepath.Join(outdir, outfile)
	f, err := os.Create(path)
	if err != nil {
		return nil, nil, "", err
	}
	writer := bufio.NewWriter(f)
	return writer, f, sname, nil
}

func safeTypeVarName(rtype rdl.TypeRef) rdl.TypeName {
	tokens := strings.Split(string(rtype), ".")
	return rdl.TypeName(capitalize(strings.Join(tokens, "")))
}
