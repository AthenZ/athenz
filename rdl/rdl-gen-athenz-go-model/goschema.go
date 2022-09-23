// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package main

import (
	"bufio"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	genutil "github.com/ardielle/ardielle-go/gen"
	"github.com/ardielle/ardielle-go/rdl"
)

type schemaGenerator struct {
	registry    rdl.TypeRegistry
	schema      *rdl.Schema
	name        string
	writer      *bufio.Writer
	err         error
	banner      string
	ns          string
	librdl      string
	rdlprefix   string
	prefixEnums bool
}

// GenerateGoSchema generates the code to regenerate the Schema
func GenerateGoSchema(banner string, schema *rdl.Schema, outdir string, ns string, librdl string, prefixEnums bool) error {
	name := strings.ToLower(string(schema.Name))
	if strings.HasSuffix(outdir, ".go") {
		name = filepath.Base(outdir)
		outdir = filepath.Dir(outdir)
	} else {
		name = name + "_schema.go"
	}
	err := os.MkdirAll(outdir, 0755)
	if err != nil {
		return err
	}
	filePath := outdir + "/" + name
	out, file, _, err := genutil.OutputWriter(filePath, "", ".go")
	if err != nil {
		return err
	}
	if file != nil {
		defer func() {
			file.Close()
			err := goFmt(filePath)
			if err != nil {
				fmt.Println("Warning: could not format go code:", err)
			}
		}()
	}
	rdlprefix := "rdl."
	if schema.Name == "rdl" {
		rdlprefix = ""
	}
	gen := &schemaGenerator{rdl.NewTypeRegistry(schema), schema, capitalize(string(schema.Name)), out, nil, banner, ns, librdl, rdlprefix, prefixEnums}
	gen.emit(GenerationHeader(banner))
	gen.emit("\n\npackage " + GenerationPackage(gen.schema, gen.ns) + "\n\n")
	gen.emit("import (\n")
	gen.emit("\t\"log\"\n")
	gen.emit("\n")
	if gen.schema.Name != "rdl" {
		gen.emit("\trdl \"" + librdl + "\"\n")
	}
	gen.emit(")\n\n")
	gen.emit("var schema *" + rdlprefix + "Schema\n\n")
	gen.emit(fmt.Sprintf("func init() {\n\tsb := %sNewSchemaBuilder(%q)\n", rdlprefix, schema.Name))
	if schema.Version != nil {
		gen.emit(fmt.Sprintf("\tsb.Version(%d)\n", *schema.Version))
	}
	if schema.Namespace != "" {
		gen.emit(fmt.Sprintf("\tsb.Namespace(%q)\n", schema.Namespace))
	}
	if schema.Comment != "" {
		gen.emit(fmt.Sprintf("\tsb.Comment(%q)\n", schema.Comment))
	}
	gen.emit("\n")
	if gen.err == nil {
		for _, t := range schema.Types {
			gen.emitType(t)
		}
	}
	if gen.err == nil {
		for _, r := range schema.Resources {
			gen.emitResource(r)
		}
	}
	gen.emit("\tvar err error\n")
	gen.emit("\tschema, err = sb.BuildParanoid()\n")
	gen.emit("\tif err != nil {\n")
	gen.emit("\t  log.Fatalf(\"rdl: schema build failed: %s\", err)")
	gen.emit("\t}\n")
	gen.emit("}\n\n")
	gen.emit(fmt.Sprintf("func %sSchema() *%sSchema {\n", capitalize(string(schema.Name)), rdlprefix))
	gen.emit("\treturn schema\n")
	gen.emit("}\n")
	out.Flush()
	return gen.err
}

func SafeTypeVarName(rtype rdl.TypeRef) rdl.TypeName {
	tokens := strings.Split(string(rtype), ".")
	return rdl.TypeName(capitalize(strings.Join(tokens, "")))
}

func (gen *schemaGenerator) emitResource(rez *rdl.Resource) {
	rTypeName := rez.Type
	if rez.Method == "PUT" || rez.Method == "POST" {
		for _, ri := range rez.Inputs {
			if !ri.PathParam && ri.QueryParam == "" && ri.Header == "" {
				rTypeName = ri.Type
				break
			}
		}
	}
	rVarName := SafeTypeVarName(rTypeName)
	rname := fmt.Sprintf("m%s%s", capitalize(strings.ToLower(rez.Method)), rVarName)
	if rez.Name != "" {
		rname = "m" + capitalize(string(rez.Name))
	}
	gen.emit(fmt.Sprintf("\t%s := rdl.NewResourceBuilder(%q, %q, %q)\n", rname, rez.Type, rez.Method, rez.Path))
	if rez.Comment != "" {
		gen.emit(fmt.Sprintf("\t%s.Comment(%q)\n", rname, rez.Comment))
	}
	if rez.Name != "" {
		gen.emit(fmt.Sprintf("\t%s.Name(%q)\n", rname, rez.Name))
	}
	for _, ri := range rez.Inputs {
		def := "nil"
		if ri.Default != nil {
			switch gen.registry.FindBaseType(ri.Type) {
			case rdl.BaseTypeEnum:
				def = fmt.Sprintf("%q", ri.Default)
			default:
				switch ri.Default.(type) {
				case string:
					def = fmt.Sprintf("%q", ri.Default)
				default:
					def = fmt.Sprint(ri.Default)
				}
			}
		}
		gen.emit(fmt.Sprintf("\t%s.Input(%q, %q, %v, %q, %q, %v, %v, %q)\n", rname, ri.Name, ri.Type, ri.PathParam, ri.QueryParam, ri.Header, ri.Optional, def, ri.Comment))
	}
	for _, ro := range rez.Outputs {
		gen.emit(fmt.Sprintf("\t%s.Output(%q, %q, %q, %v, %q)\n", rname, ro.Name, ro.Type, ro.Header, ro.Optional, ro.Comment))
	}
	if rez.Auth != nil {
		gen.emit(fmt.Sprintf("\t%s.Auth(%q, %q, %v, %q)\n", rname, rez.Auth.Action, rez.Auth.Resource, rez.Auth.Authenticate, rez.Auth.Domain))
	}
	if rez.Expected != "OK" {
		gen.emit(fmt.Sprintf("\t%s.Expected(%q)\n", rname, rez.Expected))
	}
	//build a sorted order for the exceptions, to make them predictable. Go randomizes the order otherwise.
	var syms []string
	for sym := range rez.Exceptions {
		syms = append(syms, sym)
	}
	sort.Strings(syms)
	for _, sym := range syms {
		re := rez.Exceptions[sym]
		gen.emit(fmt.Sprintf("\t%s.Exception(%q, %q, %q)\n", rname, sym, re.Type, re.Comment))
	}
	gen.emit(fmt.Sprintf("\tsb.AddResource(%s.Build())\n\n", rname))
}

func (gen *schemaGenerator) emitType(typedef *rdl.Type) {
	switch typedef.Variant {
	case rdl.TypeVariantAliasTypeDef:
		gen.emitAliasType(typedef.AliasTypeDef)
	case rdl.TypeVariantBytesTypeDef:
		gen.emitBytesType(typedef.BytesTypeDef)
	case rdl.TypeVariantNumberTypeDef:
		gen.emitNumberType(typedef.NumberTypeDef)
	case rdl.TypeVariantStringTypeDef:
		gen.emitStringType(typedef.StringTypeDef)
	case rdl.TypeVariantStructTypeDef:
		gen.emitStructType(typedef.StructTypeDef)
	case rdl.TypeVariantArrayTypeDef:
		gen.emitArrayType(typedef.ArrayTypeDef)
	case rdl.TypeVariantMapTypeDef:
		gen.emitMapType(typedef.MapTypeDef)
	case rdl.TypeVariantEnumTypeDef:
		gen.emitEnumType(typedef.EnumTypeDef)
	case rdl.TypeVariantUnionTypeDef:
		gen.emitUnionType(typedef.UnionTypeDef)
	default:
		fmt.Println("[Warning: user type list contains a non user type:", typedef)
	}
}

func (gen *schemaGenerator) emitStringType(typedef *rdl.StringTypeDef) {
	varname := "t" + goTypeName(typedef.Name)
	gen.emit(fmt.Sprintf("\t%s := %sNewStringTypeBuilder(%q)\n", varname, gen.rdlprefix, typedef.Name))
	if typedef.Comment != "" {
		gen.emit(fmt.Sprintf("\t%s.Comment(%q)\n", varname, typedef.Comment))
	}
	if typedef.Pattern != "" {
		gen.emit(fmt.Sprintf("\t%s.Pattern(%q)\n", varname, typedef.Pattern))
	}
	if typedef.MinSize != nil {
		gen.emit(fmt.Sprintf("\t%s.MinSize(%d)\n", varname, *typedef.MinSize))
	}
	if typedef.MaxSize != nil {
		gen.emit(fmt.Sprintf("\t%s.MaxSize(%d)\n", varname, *typedef.MaxSize))
	}
	gen.emit(fmt.Sprintf("\tsb.AddType(%s.Build())\n\n", varname))
}

func (gen *schemaGenerator) emitBytesType(typedef *rdl.BytesTypeDef) {
	varname := "t" + goTypeName(typedef.Name)
	gen.emit(fmt.Sprintf("\t%s := %sNewBytesTypeBuilder(%q)\n", varname, gen.rdlprefix, typedef.Name))
	if typedef.Comment != "" {
		gen.emit(fmt.Sprintf("\t%s.Comment(%q)\n", varname, typedef.Comment))
	}
	if typedef.MinSize != nil {
		gen.emit(fmt.Sprintf("\t%s.MinSize(%d)\n", varname, *typedef.MinSize))
	}
	if typedef.MaxSize != nil {
		gen.emit(fmt.Sprintf("\t%s.MaxSize(%d)\n", varname, *typedef.MaxSize))
	}
	gen.emit(fmt.Sprintf("\tsb.AddType(%s.Build())\n\n", varname))
}

func numericValueString(n rdl.Number) string {
	switch n.Variant {
	case rdl.NumberVariantInt8:
		return fmt.Sprint(*n.Int8)
	case rdl.NumberVariantInt16:
		return fmt.Sprint(*n.Int16)
	case rdl.NumberVariantInt32:
		return fmt.Sprint(*n.Int32)
	case rdl.NumberVariantInt64:
		return fmt.Sprint(*n.Int64)
	case rdl.NumberVariantFloat32:
		return fmt.Sprint(*n.Float32)
	case rdl.NumberVariantFloat64:
		return fmt.Sprint(*n.Float64)
	}
	return ""
}

func (gen *schemaGenerator) emitNumberType(typedef *rdl.NumberTypeDef) {
	varname := "t" + goTypeName(typedef.Name)
	gen.emit(fmt.Sprintf("\t%s := %sNewNumberTypeBuilder(%q, %q)\n", varname, gen.rdlprefix, typedef.Type, typedef.Name))
	if typedef.Comment != "" {
		gen.emit(fmt.Sprintf("\t%s.Comment(%q)\n", varname, typedef.Comment))
	}
	if typedef.Min != nil {
		gen.emit(fmt.Sprintf("\t%s.Min(%v)\n", varname, numericValueString(*typedef.Min)))
	}
	if typedef.Max != nil {
		gen.emit(fmt.Sprintf("\t%s.Max(%v)\n", varname, numericValueString(*typedef.Max)))
	}
	gen.emit(fmt.Sprintf("\tsb.AddType(%s.Build())\n\n", varname))
}

func (gen *schemaGenerator) emitAliasType(typedef *rdl.AliasTypeDef) {
	varname := "t" + goTypeName(typedef.Name)
	gen.emit(fmt.Sprintf("\t%s := %sNewAliasTypeBuilder(%q, %q)\n", varname, gen.rdlprefix, typedef.Type, typedef.Name))
	if typedef.Comment != "" {
		gen.emit(fmt.Sprintf("\t%s.Comment(%q)\n", varname, typedef.Comment))
	}
	gen.emit(fmt.Sprintf("\tsb.AddType(%s.Build())\n\n", varname))
}

func (gen *schemaGenerator) emitStructType(typedef *rdl.StructTypeDef) {
	varname := "t" + goTypeName(typedef.Name)
	gen.emit(fmt.Sprintf("\t%s := %sNewStructTypeBuilder(%q, %q)\n", varname, gen.rdlprefix, typedef.Type, typedef.Name))
	if typedef.Comment != "" {
		gen.emit(fmt.Sprintf("\t%s.Comment(%q)\n", varname, typedef.Comment))
	}
	for _, f := range typedef.Fields {
		if f.Type == "Array" {
			if f.Items != "" {
				gen.emit(fmt.Sprintf("\t%s.ArrayField(%q, %q, %v, %q)\n", varname, f.Name, f.Items, f.Optional, f.Comment))
				continue
			}
		} else if f.Type == "Map" {
			if f.Keys != "" && f.Items != "" {
				gen.emit(fmt.Sprintf("\t%s.MapField(%q, %q, %q, %v, %q)\n", varname, f.Name, f.Keys, f.Items, f.Optional, f.Comment))
				continue
			}
		}
		def := "nil"
		if f.Default != nil {
			switch gen.registry.FindBaseType(f.Type) {
			case rdl.BaseTypeEnum:
				if gen.prefixEnums {
					def = fmt.Sprint(f.Default)
					def = genutil.SnakeToCamel(def)
					def = capitalize(string(f.Type)) + def
				} else {
					def = fmt.Sprint(f.Default)
				}
			default:
				switch f.Default.(type) {
				case string:
					def = fmt.Sprintf("%q", f.Default)
				default:
					def = fmt.Sprint(f.Default)
				}
			}
		}
		gen.emit(fmt.Sprintf("\t%s.Field(%q, %q, %v, %v, %q)\n", varname, f.Name, f.Type, f.Optional, def, f.Comment))
	}
	gen.emit(fmt.Sprintf("\tsb.AddType(%s.Build())\n\n", varname))
}

func (gen *schemaGenerator) emitArrayType(typedef *rdl.ArrayTypeDef) {
	varname := "t" + goTypeName(typedef.Name)
	gen.emit(fmt.Sprintf("\t%s := %sNewArrayTypeBuilder(%q, %q)\n", varname, gen.rdlprefix, typedef.Type, typedef.Name))
	if typedef.Comment != "" {
		gen.emit(fmt.Sprintf("\t%s.Comment(%q)\n", varname, typedef.Comment))
	}
	if typedef.Items != "" {
		gen.emit(fmt.Sprintf("\t%s.Items(%q)\n", varname, typedef.Items))
	}
	gen.emit(fmt.Sprintf("\tsb.AddType(%s.Build())\n\n", varname))
}

func (gen *schemaGenerator) emitMapType(typedef *rdl.MapTypeDef) {
	varname := "t" + goTypeName(typedef.Name)
	gen.emit(fmt.Sprintf("\t%s := %sNewMapTypeBuilder(%q, %q)\n", varname, gen.rdlprefix, typedef.Type, typedef.Name))
	if typedef.Comment != "" {
		gen.emit(fmt.Sprintf("\t%s.Comment(%q)\n", varname, typedef.Comment))
	}
	if typedef.Keys != "" {
		gen.emit(fmt.Sprintf("\t%s.Keys(%q)\n", varname, typedef.Keys))
	}
	if typedef.Items != "" {
		gen.emit(fmt.Sprintf("\t%s.Items(%q)\n", varname, typedef.Items))
	}
	gen.emit(fmt.Sprintf("\tsb.AddType(%s.Build())\n\n", varname))
}

func (gen *schemaGenerator) emitEnumType(typedef *rdl.EnumTypeDef) {
	varname := "t" + goTypeName(typedef.Name)
	gen.emit(fmt.Sprintf("\t%s := %sNewEnumTypeBuilder(%q, %q)\n", varname, gen.rdlprefix, typedef.Type, typedef.Name))
	if typedef.Comment != "" {
		gen.emit(fmt.Sprintf("\t%s.Comment(%q)\n", varname, typedef.Comment))
	}
	for _, f := range typedef.Elements {
		gen.emit(fmt.Sprintf("\t%s.Element(%q, %q)\n", varname, f.Symbol, f.Comment))
	}
	gen.emit(fmt.Sprintf("\tsb.AddType(%s.Build())\n\n", varname))
}

func (gen *schemaGenerator) emitUnionType(typedef *rdl.UnionTypeDef) {
	varname := "t" + goTypeName(typedef.Name)
	gen.emit(fmt.Sprintf("\t%s := %sNewUnionTypeBuilder(%q, %q)\n", varname, gen.rdlprefix, typedef.Type, typedef.Name))
	if typedef.Comment != "" {
		gen.emit(fmt.Sprintf("\t%s.Comment(%q)\n", varname, typedef.Comment))
	}
	for _, variant := range typedef.Variants {
		gen.emit(fmt.Sprintf("\t%s.Variant(%q)\n", varname, variant))
	}
	gen.emit(fmt.Sprintf("\tsb.AddType(%s.Build())\n\n", varname))
}

func (gen *schemaGenerator) emit(s string) {
	if gen.err == nil {
		_, err := gen.writer.WriteString(s)
		if err != nil {
			gen.err = err
		}
	}
}
