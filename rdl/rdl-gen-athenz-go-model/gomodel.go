// Copyright The Athenz Authors
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package main

import (
	"bufio"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"

	genutil "github.com/ardielle/ardielle-go/gen"
	"github.com/ardielle/ardielle-go/rdl"
)

type GeneratorParams struct {
	Outdir         string
	Banner         string
	Namespace      string
	UntaggedUnions []string
	LibRdl         string
	PrefixEnums    bool
	PreciseTypes   bool
	GenerateSchema bool
}

type modelGenerator struct {
	registry       rdl.TypeRegistry
	schema         *rdl.Schema
	writer         *bufio.Writer
	librdl         string
	prefixEnums    bool
	precise        bool
	err            error
	untaggedUnions []string
	ns             string
	rdl            bool
}

// GenerateGoModel generates the model code for the types defined in the RDL schema.
func GenerateAthenzGoModel(schema *rdl.Schema, params *GeneratorParams) error {
	name := strings.ToLower(string(schema.Name))
	outdir := params.Outdir
	if outdir == "" {
		outdir = "."
		name = name + "_model.go"
	} else if strings.HasSuffix(outdir, ".go") {
		name = filepath.Base(outdir)
		outdir = filepath.Dir(outdir)
	} else {
		name = name + "_model.go"
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
	gen := &modelGenerator{
		registry:       rdl.NewTypeRegistry(schema),
		schema:         schema,
		writer:         out,
		librdl:         params.LibRdl,
		prefixEnums:    params.PrefixEnums,
		precise:        params.PreciseTypes,
		err:            nil,
		untaggedUnions: params.UntaggedUnions,
		ns:             params.Namespace,
		rdl:            schema.Name == "rdl",
	}
	gen.emitHeader(params.Banner)
	if gen.err == nil {
		for _, t := range schema.Types {
			gen.emitType(t)
		}
	}
	out.Flush()
	if gen.err == nil {
		if params.GenerateSchema {
			gen.err = GenerateGoSchema(params.Banner, schema, outdir, params.Namespace, params.LibRdl, params.PrefixEnums)
		}
	}
	return gen.err
}

func (gen *modelGenerator) isUntaggedUnion(s rdl.TypeName) bool {
	ss := string(s)
	for _, st := range gen.untaggedUnions {
		if ss == st {
			return true
		}
	}
	return false
}

func (gen *modelGenerator) emit(s string) {
	if gen.err == nil {
		_, err := gen.writer.WriteString(s)
		if err != nil {
			gen.err = err
		}
	}
}

func (gen *modelGenerator) structHasFieldDefault(t *rdl.StructTypeDef) bool {

	flds := genutil.FlattenedFields(gen.registry, gen.registry.FindType(t.Type))
	flds = append(flds, t.Fields...)

	for _, f := range flds {
		if !f.Optional {
			switch gen.registry.FindBaseType(f.Type) {
			case rdl.BaseTypeArray, rdl.BaseTypeMap, rdl.BaseTypeStruct:
				return true
			}
		}
		if f.Default != nil {
			switch gen.registry.FindBaseType(f.Type) {
			case rdl.BaseTypeString, rdl.BaseTypeSymbol, rdl.BaseTypeUUID, rdl.BaseTypeTimestamp:
				switch s := (f.Default).(type) {
				case string:
					if s != "" {
						return true
					}
				}
			case rdl.BaseTypeEnum:
				switch s := (f.Default).(type) {
				case string:
					if s != "" {
						return true
					}
				}
			case rdl.BaseTypeInt8, rdl.BaseTypeInt16, rdl.BaseTypeInt32, rdl.BaseTypeInt64, rdl.BaseTypeFloat32, rdl.BaseTypeFloat64:
				switch n := f.Default.(type) {
				case float64:
					if n != 0 {
						return true
					}
				}
			case rdl.BaseTypeBool:
				switch b := f.Default.(type) {
				case bool:
					if b {
						return true
					}
				}
			}
		}
	}
	return false
}

func (gen *modelGenerator) requiredImports(t *rdl.Type, imports map[string]string, visited map[rdl.TypeName]rdl.TypeName) {
	tName, _, _ := rdl.TypeInfo(t)
	if _, ok := visited[tName]; ok {
		return
	}
	visited[tName] = tName
	if strings.HasPrefix(string(tName), "rdl.") && !gen.rdl {
		imports[gen.librdl] = "rdl"
	}
	b := gen.registry.BaseType(t)
	switch b {
	case rdl.BaseTypeTimestamp, rdl.BaseTypeUUID:
		if !gen.rdl {
			imports[gen.librdl] = "rdl"
		}
	case rdl.BaseTypeEnum:
		imports["encoding/json"] = ""
		imports["fmt"] = ""
		break
	case rdl.BaseTypeUnion:
		imports["encoding/json"] = ""
		imports["fmt"] = ""
		break
	case rdl.BaseTypeArray:
		if t.ArrayTypeDef != nil {
			gen.requiredImports(gen.registry.FindType(t.ArrayTypeDef.Items), imports, visited)
		}
	case rdl.BaseTypeMap:
		if t.MapTypeDef != nil {
			gen.requiredImports(gen.registry.FindType(t.MapTypeDef.Keys), imports, visited)
			gen.requiredImports(gen.registry.FindType(t.MapTypeDef.Items), imports, visited)
		}
	case rdl.BaseTypeStruct:
		if !gen.rdl {
			imports[gen.librdl] = "rdl"
		}
		imports["encoding/json"] = ""
		if t.StructTypeDef != nil && t.StructTypeDef.Fields != nil {
			for _, f := range t.StructTypeDef.Fields {
				if !f.Optional {
					switch gen.registry.FindBaseType(f.Type) {
					case rdl.BaseTypeString, rdl.BaseTypeArray, rdl.BaseTypeMap, rdl.BaseTypeStruct:
						imports["fmt"] = ""
					}
				}
				if f.Items != "" {
					gen.requiredImports(gen.registry.FindType(f.Items), imports, visited)
				} else if f.Keys != "" {
					gen.requiredImports(gen.registry.FindType(f.Keys), imports, visited)
				} else {
					t := gen.registry.FindType(f.Type)
					if t != nil {
						gen.requiredImports(t, imports, visited)
					}
				}
			}
		}
	}
}

func (gen *modelGenerator) emitHeader(banner string) {
	imports := make(map[string]string, 0)
	visited := make(map[rdl.TypeName]rdl.TypeName, 0)
	for _, t := range gen.schema.Types {
		gen.requiredImports(t, imports, visited)
	}
	gen.emit(GenerationHeader(banner))
	gen.emit("\n\npackage " + GenerationPackage(gen.schema, gen.ns) + "\n")
	if len(imports) > 0 {
		rdlEmitted := false
		jsonEmitted := false
		fmtEmitted := false
		var imp sort.StringSlice
		for k := range imports {
			if k == string(gen.schema.Name) {
				continue
			}
			kk := fmt.Sprintf("%q", k)
			if k == "fmt" {
				fmtEmitted = true
			} else if k == "encoding/json" {
				jsonEmitted = true
			}
			n := imports[k]
			if n != "" {
				if n == "rdl" {
					rdlEmitted = true
				}
				kk = n + " " + kk
			}
			imp = append(imp, kk)
		}
		imp.Sort()
		gen.emit("\nimport (\n")
		for _, k := range imp {
			gen.emit("\t" + k + "\n")
		}
		gen.emit(")\n")
		if rdlEmitted {
			gen.emit("\nvar _ = rdl.Version\n")
		}
		if jsonEmitted {
			if !rdlEmitted {
				gen.emit("\n")
			}
			gen.emit("var _ = json.Marshal\n")
		}
		if fmtEmitted {
			if !jsonEmitted && !rdlEmitted {
				gen.emit("\n")
			}
			gen.emit("var _ = fmt.Printf\n")
		}
	}
}

func (gen *modelGenerator) emitTypeComment(t *rdl.Type) {
	tName, _, tComment := rdl.TypeInfo(t)
	s := string(tName) + " -"
	if tComment != "" {
		s += " " + tComment
	}
	gen.emit(formatComment(s, 0, 80))
}

func goType(reg rdl.TypeRegistry, rdlType rdl.TypeRef, optional bool, items rdl.TypeRef, keys rdl.TypeRef, precise bool, reference bool) string {
	return goType2(reg, rdlType, optional, items, keys, precise, reference, "")
}

func goType2(reg rdl.TypeRegistry, rdlType rdl.TypeRef, optional bool, items rdl.TypeRef, keys rdl.TypeRef, precise bool, reference bool, packageName string) string {
	rdlPrefix := "rdl."
	if reg.Name() == "rdl" {
		rdlPrefix = ""
	}
	cleanType := string(rdlType)
	if !strings.HasPrefix(cleanType, "rdl.") {
		cleanType = capitalize(strings.Replace(string(rdlType), ".", "_", -1))
	}
	prefix := ""
	if optional {
		prefix = "*"
	}
	t := reg.FindType(rdlType)
	if t.Variant == 0 {
		panic("Cannot find type '" + rdlType + "'")
	}
	lrdlType := strings.ToLower(string(rdlType))
	if precise {
		switch lrdlType {
		case "string":
			return "string"
		case "symbol":
			return rdlPrefix + "Symbol"
		case "bool", "int32", "int64", "int16", "int8", "float64", "float32":
			return prefix + strings.ToLower(cleanType)
		default:
			bt := reg.BaseType(t)
			switch bt {
			case rdl.BaseTypeString, rdl.BaseTypeSymbol:
				return cleanType
			case rdl.BaseTypeInt8, rdl.BaseTypeInt16, rdl.BaseTypeInt32, rdl.BaseTypeInt64, rdl.BaseTypeFloat32, rdl.BaseTypeFloat64, rdl.BaseTypeBool:
				return prefix + cleanType
			case rdl.BaseTypeTimestamp, rdl.BaseTypeUUID:
				fullTypeName := rdlPrefix + cleanType
				return prefix + fullTypeName
			default:
				if lrdlType == "struct" {
					fullTypeName := rdlPrefix + cleanType
					return prefix + fullTypeName
				}
			}
		}
	} else {
		switch lrdlType {
		case "timestamp":
			return prefix + rdlPrefix + "Timestamp"
		case "uuid":
			return prefix + rdlPrefix + "UUID"
		case "struct":
			return prefix + rdlPrefix + "Struct"
		}
	}
	bt := reg.BaseType(t)
	switch bt {
	case rdl.BaseTypeAny:
		return "interface{}"
	case rdl.BaseTypeString:
		return "string"
	case rdl.BaseTypeSymbol:
		return rdlPrefix + "Symbol"
	case rdl.BaseTypeBool:
		return prefix + "bool"
	case rdl.BaseTypeInt8, rdl.BaseTypeInt16, rdl.BaseTypeInt32, rdl.BaseTypeInt64, rdl.BaseTypeFloat32, rdl.BaseTypeFloat64:
		return prefix + strings.ToLower(bt.String())
	case rdl.BaseTypeArray:
		if reference {
			name := "Array"
			if t.ArrayTypeDef != nil {
				name = string(t.ArrayTypeDef.Name)
			}
			if name != "Array" {
				return name
			}
		}
		i := rdl.TypeRef("Any")
		switch t.Variant {
		case rdl.TypeVariantArrayTypeDef:
			i = t.ArrayTypeDef.Items
		default:
			if items != "" {
				i = items
			}
		}
		gitems := goType2(reg, i, false, "", "", precise, reference, packageName)
		return "[]" + gitems
	case rdl.BaseTypeMap:
		if reference {
			//we check if we have defined a type, i.e. the type name is not "Map"
			name := rdl.TypeName("Map")
			if t.MapTypeDef != nil {
				name = t.MapTypeDef.Name
			} else if t.AliasTypeDef != nil {
				name = t.AliasTypeDef.Name
			}
			if name != "Map" {
				return string(name)
			}
		}
		k := rdl.TypeRef("Any")
		i := rdl.TypeRef("Any")
		switch t.Variant {
		case rdl.TypeVariantMapTypeDef:
			k = t.MapTypeDef.Keys
			i = t.MapTypeDef.Items
		default:
			if keys != "" {
				k = keys
			}
			if items != "" {
				i = items
			}
		}
		gkeys := goType2(reg, k, false, "", "", precise, reference, packageName)
		gitems := goType2(reg, i, false, "", "", precise, reference, packageName)
		return "map[" + gkeys + "]" + gitems
	case rdl.BaseTypeStruct:
		switch t.Variant {
		case rdl.TypeVariantAliasTypeDef:
			if t.AliasTypeDef.Name == "Struct" {
				return prefix + "map[string]interface{}"
			}
		}
		if packageName != "" {
			return "*" + packageName + "." + cleanType
		}
		return "*" + cleanType
	case rdl.BaseTypeUnion:
		return "*" + cleanType
	case rdl.BaseTypeEnum:
		return prefix + cleanType
	case rdl.BaseTypeBytes:
		return "[]byte"
	default:
		return prefix + cleanType
	}
}

func (gen *modelGenerator) emitType(t *rdl.Type) {
	if gen.err == nil {
		tName, _, _ := rdl.TypeInfo(t)
		if strings.HasPrefix(string(tName), "rdl.") {
			return
		}
		tName = goTypeName(tName)
		bt := gen.registry.BaseType(t)
		switch bt {
		case rdl.BaseTypeAny:
			gen.emit("\n")
			gen.emitTypeComment(t)
			gen.emit(fmt.Sprintf("type %s interface{}\n", tName))
		case rdl.BaseTypeString, rdl.BaseTypeBool, rdl.BaseTypeInt8, rdl.BaseTypeInt16, rdl.BaseTypeInt32, rdl.BaseTypeInt64, rdl.BaseTypeFloat32, rdl.BaseTypeFloat64, rdl.BaseTypeSymbol:
			if gen.precise {
				gen.emit("\n")
				gen.emitTypeComment(t)
				gen.emit(fmt.Sprintf("type %s %s\n", tName, goType(gen.registry, rdl.TypeRef(bt.String()), false, "", "", gen.precise, false)))
			}
		case rdl.BaseTypeStruct:
			gen.emit("\n")
			gen.emitStruct(t)
		case rdl.BaseTypeUnion:
			gen.emit("\n")
			gen.emitUnion(t)
		case rdl.BaseTypeArray:
			gen.emit("\n")
			gen.emitArray(t)
		case rdl.BaseTypeMap:
			gen.emit("\n")
			gen.emitMap(t)
		case rdl.BaseTypeEnum:
			gen.emit("\n")
			gen.emitTypeComment(t)
			gen.emitEnum(t)
		}
	}
}

func goTypeName(name rdl.TypeName) rdl.TypeName {
	tokens := strings.Split(string(name), ".")
	return rdl.TypeName(capitalize(strings.Join(tokens, "_")))
}

func (gen *modelGenerator) emitUnion(t *rdl.Type) {
	tName, _, _ := rdl.TypeInfo(t)
	ut := t.UnionTypeDef
	uName := capitalize(string(tName))
	gen.emit(fmt.Sprintf("// %sVariantTag - generated to support %s\n", uName, uName))
	gen.emit(fmt.Sprintf("type %sVariantTag int\n\n", uName))
	gen.emit("// Supporting constants\n")
	gen.emit("const (\n")
	gen.emit(fmt.Sprintf("\t_ %sVariantTag = iota\n", uName))
	for _, v := range ut.Variants {
		uV := capitalize(string(v))
		gen.emit(fmt.Sprintf("\t%sVariant%s\n", uName, uV))
	}
	gen.emit(")\n\n")

	maxKeyLen := len("Variant")
	for _, v := range ut.Variants {
		if len(v) > maxKeyLen {
			maxKeyLen = len(v)
		}
	}
	gen.emitTypeComment(t)
	gen.emit(fmt.Sprintf("type %s struct {\n", uName))
	s := leftJustified("Variant", maxKeyLen)
	vtag := uName + "VariantTag"
	gen.emit(fmt.Sprintf("\t%s %s `json:\"-\" rdl:\"union\"`\n", s, vtag))
	maxVarLen := maxKeyLen + 1
	if len(vtag) > maxVarLen {
		maxVarLen = len(vtag)
	}
	for _, v := range ut.Variants {
		uV := capitalize(string(v))
		vType := goType(gen.registry, v, true, "", "", gen.precise, true)
		tag := fmt.Sprintf("`json:\"%s,omitempty\" yaml:\",omitempty\"`", v)
		s := leftJustified(uV, maxKeyLen)
		gen.emit(fmt.Sprintf("\t%s %s %s\n", s, leftJustified(vType, maxVarLen), tag))
	}
	gen.emit("}\n\n")
	gen.emit(fmt.Sprintf("func (u %s) String() string {\n", uName))
	gen.emit("\tswitch u.Variant {\n")
	for _, v := range ut.Variants {
		uV := capitalize(string(v))
		gen.emit(fmt.Sprintf("\tcase %sVariant%s:\n", uName, uV))
		gen.emit(fmt.Sprintf("\t\treturn fmt.Sprintf(\"%%v\", u.%s)\n", uV))
	}
	gen.emit("\tdefault:\n")
	gen.emit(fmt.Sprintf("\t\treturn \"<%s uninitialized>\"\n", uName))
	gen.emit("\t}\n")
	gen.emit("}\n\n")
	gen.emit(fmt.Sprintf("// Validate for %s\n", uName))
	gen.emit(fmt.Sprintf("func (p *%s) Validate() error {\n", uName))
	gen.emit("\t")
	for _, v := range ut.Variants {
		gen.emit(fmt.Sprintf("if p.%s != nil {\n\t\tp.Variant = %sVariant%s\n\t} else ", v, uName, v))
	}
	gen.emit(fmt.Sprintf("{\n\t\treturn fmt.Errorf(\"%s: Missing required variant\")\n\t}\n", uName))
	gen.emit("\treturn nil\n")
	gen.emit("}\n")

	if gen.isUntaggedUnion(tName) {
		gen.emitUntaggedUnionSerializer(ut, tName)
	} else {
		gen.emit(fmt.Sprintf("\ntype raw%s %s\n\n", uName, uName))
		gen.emit(fmt.Sprintf("// UnmarshalJSON for %s\n", uName))
		gen.emit(fmt.Sprintf("func (p *%s) UnmarshalJSON(b []byte) error {\n", uName))
		gen.emit(fmt.Sprintf("\tvar tmp raw%s\n", uName))
		gen.emit("\tif err := json.Unmarshal(b, &tmp); err != nil {\n")
		gen.emit("\t\treturn err\n")
		gen.emit("\t}\n")
		gen.emit(fmt.Sprintf("\t*p = %s(tmp)\n", uName))
		gen.emit("\treturn p.Validate()\n")
		gen.emit("}\n")
	}
}

func (gen *modelGenerator) emitUntaggedUnionSerializer(ut *rdl.UnionTypeDef, uName rdl.TypeName) {
	gen.emit(fmt.Sprintf("\nfunc check%sStructFields(repr map[string]interface{}, fields map[string]bool) bool {\n", uName))
	gen.emit("\tfor name, required := range fields {\n")
	gen.emit("\t\tif _, present := repr[name]; required && !present {\n")
	gen.emit("\t\t\treturn false\n")
	gen.emit("\t\t}\n")
	gen.emit("\t}\n")
	gen.emit("\tfor name := range repr {\n")
	gen.emit("\t\tif _, ok := fields[name]; !ok {\n")
	gen.emit("\t\t\treturn false\n")
	gen.emit("\t\t}\n")
	gen.emit("\t}\n")
	gen.emit("\treturn true\n")
	gen.emit("}\n\n")

	for _, v := range ut.Variants {
		uV := capitalize(string(v))
		t := gen.registry.FindType(v)
		switch t.Variant {
		case rdl.TypeVariantStructTypeDef:
			names := ""
			for _, f := range genutil.FlattenedFields(gen.registry, t) {
				s := fmt.Sprintf("%q", f.Name)
				if !f.Optional && f.Default == nil {
					s = s + ": true"
				} else {
					s = s + ": false"
				}
				if names == "" {
					names = s
				} else {
					names = names + ", " + s
				}
			}
			if names != "" {
				names = "map[string]bool{" + names + "}"
				gen.emit(fmt.Sprintf("func make%sVariant%s(b []byte, u *%s, fields map[string]interface{}) bool {\n", uName, uV, uName))
				gen.emit(fmt.Sprintf("\tif check%sStructFields(fields, %s) {\n", uName, names))
				gen.emit(fmt.Sprintf("\t\tvar o %s\n", uV))
				gen.emit("\t\tif err := json.Unmarshal(b, &o); err == nil {\n")
				gen.emit(fmt.Sprintf("\t\t\tup := new(%s)\n", uName))
				gen.emit(fmt.Sprintf("\t\t\tup.Variant = %sVariant%s\n", uName, uV))
				gen.emit(fmt.Sprintf("\t\t\tup.%s = &o\n", uV))
				gen.emit("\t\t\t*u = *up\n")
				gen.emit("\t\t\treturn true\n")
				gen.emit("\t\t}\n")
				gen.emit("\t}\n")
				gen.emit("\treturn false\n")
				gen.emit("}\n\n")
			}
		default:
			gen.err = fmt.Errorf("untagged union serializer only supported for struct type unions")
			return
		}
	}

	gen.emit(fmt.Sprintf("// UnmarshalJSON for %s\n", uName))
	gen.emit(fmt.Sprintf("func (u *%s) UnmarshalJSON(b []byte) error {\n", uName))
	gen.emit("\tvar tmp interface{}\n")
	gen.emit("\tif err := json.Unmarshal(b, &tmp); err != nil {\n")
	gen.emit("\t\treturn err\n")
	gen.emit("\t}\n")
	gen.emit("\tswitch v := tmp.(type) {\n")
	gen.emit("\tcase map[string]interface{}:\n")
	for _, v := range ut.Variants {
		uV := capitalize(string(v))
		gen.emit(fmt.Sprintf("\t\tif make%sVariant%s(b, u, v) {\n", uName, uV))
		gen.emit("\t\t\treturn nil\n")
		gen.emit("\t\t}\n")
	}
	gen.emit("\t}\n")
	gen.emit(fmt.Sprintf("\treturn fmt.Errorf(\"Cannot unmarshal JSON to union type %s\")\n", uName))
	gen.emit("}\n")

	gen.emit(fmt.Sprintf("\n// MarshalJSON for %s\n", uName))
	gen.emit(fmt.Sprintf("func (p %s) MarshalJSON() ([]byte, error) {\n", uName))
	gen.emit("\tswitch p.Variant {\n")
	for _, v := range ut.Variants {
		uV := capitalize(string(v))
		gen.emit(fmt.Sprintf("\tcase %sVariant%s:\n", uName, uV))
		gen.emit(fmt.Sprintf("\t\treturn json.Marshal(p.%s)\n", uV))
	}
	gen.emit("\t}\n")
	gen.emit(fmt.Sprintf("\treturn nil, fmt.Errorf(\"Cannot marshal uninitialized %s\")\n", uName))
	gen.emit("}\n")
}

func (gen *modelGenerator) literal(lit interface{}) string {
	switch v := lit.(type) {
	case string:
		return fmt.Sprintf("%q", v)
	case int32:
		return fmt.Sprintf("%d", v)
	case int16:
		return fmt.Sprintf("%d", v)
	case int8:
		return fmt.Sprintf("%d", v)
	case int64:
		return fmt.Sprintf("%d", v)
	case float64:
		return fmt.Sprintf("%g", v)
	case float32:
		return fmt.Sprintf("%g", v)
	default: //bool, enum
		return fmt.Sprintf("%v", lit)
	}
}

func (gen *modelGenerator) emitArray(t *rdl.Type) {
	if gen.err == nil {
		switch t.Variant {
		case rdl.TypeVariantArrayTypeDef:
			at := t.ArrayTypeDef
			gen.emitTypeComment(t)
			ftype := goType(gen.registry, at.Type, false, at.Items, "", gen.precise, false)
			gen.emit(fmt.Sprintf("type %s %s\n\n", at.Name, ftype))
		default:
			tName, tType, _ := rdl.TypeInfo(t)
			gtype := goType(gen.registry, tType, false, "", "", gen.precise, false)
			gen.emitTypeComment(t)
			gen.emit(fmt.Sprintf("type %s %s\n\n", tName, gtype))
		}
	}
}

func (gen *modelGenerator) emitMap(t *rdl.Type) {
	if gen.err == nil {
		switch t.Variant {
		case rdl.TypeVariantMapTypeDef:
			mt := t.MapTypeDef
			gen.emitTypeComment(t)
			ftype := goType(gen.registry, mt.Type, false, mt.Items, mt.Keys, gen.precise, false)
			gen.emit(fmt.Sprintf("type %s %s\n\n", mt.Name, ftype))
		default:
			tName, tType, _ := rdl.TypeInfo(t)
			gtype := goType(gen.registry, tType, false, "string", "", gen.precise, false)
			gen.emitTypeComment(t)
			gen.emit(fmt.Sprintf("type %s %s\n\n", tName, gtype))
		}
	}
}

func (gen *modelGenerator) emitStruct(t *rdl.Type) {
	if gen.err == nil {
		switch t.Variant {
		case rdl.TypeVariantStructTypeDef:
			st := t.StructTypeDef
			flattened := genutil.FlattenedFields(gen.registry, t)
			gen.emitTypeComment(t)
			gen.emitStructFields(flattened, st.Name)
			init := gen.structHasFieldDefault(st)
			gen.emit(fmt.Sprintf("\n// New%s - creates an initialized %s instance, returns a pointer to it\n", st.Name, st.Name))
			gen.emit(fmt.Sprintf("func New%s(init ...*%s) *%s {\n", st.Name, st.Name, st.Name))
			gen.emit(fmt.Sprintf("\tvar o *%s\n", st.Name))
			gen.emit("\tif len(init) == 1 {\n")
			gen.emit("\t\to = init[0]\n")
			gen.emit("\t} else {\n")
			gen.emit(fmt.Sprintf("\t\to = new(%s)\n", st.Name))
			gen.emit("\t}\n")
			if init {
				gen.emit("\treturn o.Init()\n")
			} else {
				gen.emit(fmt.Sprintf("\treturn o\n"))
			}
			gen.emit("}\n")
			if init {
				gen.emitStructInitializer(st, flattened)
			}
			gen.emitStructUnmarshaller(st, init)
			gen.emitStructValidator(st, flattened)
		case rdl.TypeVariantAliasTypeDef:
			gen.emitTypeComment(t)
			gen.emit(fmt.Sprintf("type %s rdl.Struct\n\n", t.AliasTypeDef.Name))
		default:
			panic(fmt.Sprintf("Unreasonable struct typedef: %v", t.Variant))
		}
	}
}

func (gen *modelGenerator) emitStructValidator(st *rdl.StructTypeDef, flattened []*rdl.StructFieldDef) {
	gen.emit("\n// Validate - checks for missing required fields, etc\n")
	gen.emit(fmt.Sprintf("func (self *%s) Validate() error {\n", st.Name))
	rdlPrefix := "rdl."
	if gen.rdl {
		rdlPrefix = ""
	}
	for _, f := range flattened {
		fname := capitalize(string(f.Name))
		ftype := string(f.Type)
		bt := gen.registry.FindBaseType(f.Type)
		switch bt {
		case rdl.BaseTypeString, rdl.BaseTypeSymbol:
			if !f.Optional {
				gen.emit(fmt.Sprintf("\tif self.%s == \"\" {\n", fname))
				gen.emit(fmt.Sprintf("\t\treturn fmt.Errorf(\"%s.%s is missing but is a required field\")\n", st.Name, f.Name))
			}
			if bt == rdl.BaseTypeString && fname != "String" {
				if !f.Optional {
					gen.emit("\t} else {\n")
				} else {
					gen.emit(fmt.Sprintf("\tif self.%s != \"\" {\n", fname))
				}
				gen.emit(fmt.Sprintf("\t\tval := %sValidate(%sSchema(), %q, self.%s)\n\t\tif !val.Valid {\n\t\t\treturn fmt.Errorf(\"%s.%s does not contain a valid %s (%%v)\", val.Error)\n\t\t}\n", rdlPrefix, capitalize(string(gen.schema.Name)), ftype, fname, st.Name, string(f.Name), ftype))
			}
			gen.emit("\t}\n")
		case rdl.BaseTypeTimestamp:
			if !f.Optional {
				gen.emit(fmt.Sprintf("\tif self.%s.IsZero() {\n", fname))
				gen.emit(fmt.Sprintf("\t\treturn fmt.Errorf(\"%s: Missing required field: %s\")\n", st.Name, f.Name))
				gen.emit("\t}\n")
			}
		case rdl.BaseTypeArray, rdl.BaseTypeMap, rdl.BaseTypeStruct, rdl.BaseTypeUUID:
			if !f.Optional {
				gen.emit(fmt.Sprintf("\tif self.%s == nil {\n", fname))
				gen.emit(fmt.Sprintf("\t\treturn fmt.Errorf(\"%s: Missing required field: %s\")\n", st.Name, f.Name))
				gen.emit("\t}\n")
			}
		}
	}
	gen.emit("\treturn nil\n")
	gen.emit("}\n")
}

func (gen *modelGenerator) emitStructInitializer(st *rdl.StructTypeDef, flattened []*rdl.StructFieldDef) {
	gen.emit("\n// Init - sets up the instance according to its default field values, if any\n")
	gen.emit(fmt.Sprintf("func (self *%s) Init() *%s {\n", st.Name, st.Name))
	for _, f := range flattened {
		fname := capitalize(string(f.Name))
		isRdl := false
		ftype := string(f.Type)
		if strings.HasPrefix(ftype, "rdl.") {
			isRdl = true
			ftype = capitalize(ftype[4:])
		}
		if !f.Optional {
			switch gen.registry.FindBaseType(f.Type) {
			case rdl.BaseTypeArray:
				ftype := goType(gen.registry, f.Type, false, f.Items, f.Keys, gen.precise, true)
				gen.emit(fmt.Sprintf("\tif self.%s == nil {\n", fname))
				gen.emit(fmt.Sprintf("\t\tself.%s = make(%s, 0)\n", fname, ftype))
				gen.emit("\t}\n")
			case rdl.BaseTypeMap:
				ftype := goType(gen.registry, f.Type, false, f.Items, f.Keys, gen.precise, true)
				gen.emit(fmt.Sprintf("\tif self.%s == nil {\n", fname))
				gen.emit(fmt.Sprintf("\t\tself.%s = make(%s)\n", fname, ftype))
				gen.emit("\t}\n")
			case rdl.BaseTypeStruct:
				gen.emit(fmt.Sprintf("\tif self.%s == nil {\n", fname))
				if f.Type == "Struct" {
					gen.emit(fmt.Sprintf("\t\tself.%s = make(rdl."+ftype+")\n", fname))
				} else if isRdl {
					gen.emit(fmt.Sprintf("\t\tself.%s = rdl.New%s()\n", fname, capitalize(ftype)))
				} else {
					gen.emit(fmt.Sprintf("\t\tself.%s = New%s()\n", fname, capitalize(ftype)))
				}
				gen.emit("\t}\n")
			}
		}
		if f.Default != nil {
			fdef := "nil" //the value present when not set
			ndef := "nil" //the actual value to assign, if not already a zero value
			pointerForOptional := true
			switch gen.registry.FindBaseType(f.Type) {
			case rdl.BaseTypeString, rdl.BaseTypeSymbol, rdl.BaseTypeUUID, rdl.BaseTypeTimestamp:
				fdef = "\"\""
				ndef = gen.literal(f.Default)
				pointerForOptional = false
			case rdl.BaseTypeInt8, rdl.BaseTypeInt16, rdl.BaseTypeInt32, rdl.BaseTypeInt64, rdl.BaseTypeFloat32, rdl.BaseTypeFloat64:
				fdef = "0"
				ndef = gen.literal(f.Default)
			case rdl.BaseTypeBool:
				ndef = gen.literal(f.Default)
				if !f.Optional {
					fdef = "false"
				}
			case rdl.BaseTypeEnum:
				fdef = "0"
				ndef = gen.literal(f.Default)
				if gen.prefixEnums {
					ndef = genutil.SnakeToCamel(ndef) //go conventions, should do this even without prefixEnums. Test here first.
					ndef = capitalize(ftype) + ndef
				}

			}
			if fdef != ndef {
				//if f.Optional && fdef == "nil" {
				if f.Optional && pointerForOptional {
					gen.emit(fmt.Sprintf("\tif self.%s == nil {\n", fname))
					gen.emit(fmt.Sprintf("\t\td := %s\n", ndef))
					gen.emit(fmt.Sprintf("\t\tself.%s = &d\n", fname))
				} else {
					gen.emit(fmt.Sprintf("\tif self.%s == %s {\n", fname, fdef))
					gen.emit(fmt.Sprintf("\t\tself.%s = %s\n", fname, ndef))
				}
				gen.emit("\t}\n")
			}
		}
	}
	gen.emit("\treturn self\n")
	gen.emit("}\n")
}

func (gen *modelGenerator) emitStructUnmarshaller(st *rdl.StructTypeDef, init bool) {
	name := capitalize(string(st.Name))
	gen.emit(fmt.Sprintf("\ntype raw%s %s\n\n", name, name))
	gen.emit(fmt.Sprintf("// UnmarshalJSON is defined for proper JSON decoding of a %s\n", name))
	gen.emit(fmt.Sprintf("func (self *%s) UnmarshalJSON(b []byte) error {\n", name))
	gen.emit(fmt.Sprintf("\tvar m raw%s\n", name))
	gen.emit("\terr := json.Unmarshal(b, &m)\n")
	gen.emit("\tif err == nil {\n")
	gen.emit(fmt.Sprintf("\t\to := %s(m)\n", name))
	if init {
		gen.emit(fmt.Sprintf("\t\t*self = *((&o).Init())\n"))
	} else {
		gen.emit(fmt.Sprintf("\t\t*self = o\n"))
	}
	gen.emit(fmt.Sprintf("\t\terr = self.Validate()\n"))
	gen.emit("\t}\n")
	gen.emit("\treturn err\n")
	gen.emit("}\n")
}

func (gen *modelGenerator) emitEnum(t *rdl.Type) {
	if gen.err != nil {
		return
	}
	et := t.EnumTypeDef
	name := capitalize(string(et.Name))
	gen.emit(fmt.Sprintf("type %s int\n\n", name))
	gen.emit(fmt.Sprintf("// %s constants\n", name))
	gen.emit("const (\n")
	gen.emit(fmt.Sprintf("\t_ %s = iota\n", name))
	maxKeyLen := 0
	for _, elem := range et.Elements {
		sym := string(elem.Symbol)
		if gen.prefixEnums {
			sym = genutil.SnakeToCamel(sym) //go conventions, should do this even without prefixEnums. Test here first.
			sym = name + sym
		}
		if len(sym) > maxKeyLen {
			maxKeyLen = len(sym)
		}
		gen.emit(fmt.Sprintf("\t%s\n", sym))
	}
	gen.emit(")\n\n")
	gen.emit(fmt.Sprintf("var names%s = []string{\n", name))
	for _, elem := range et.Elements {
		symName := elem.Symbol
		sym := string(symName)
		if gen.prefixEnums {
			sym = genutil.SnakeToCamel(sym) //go conventions, should do this even without prefixEnums. Test here first.
			sym = name + sym
		}
		s := leftJustified(sym+":", maxKeyLen+1)
		gen.emit(fmt.Sprintf("\t%s %q,\n", s, symName))
	}
	gen.emit("}\n\n")
	gen.emit(fmt.Sprintf("// New%s - return a string representation of the enum\n", name))
	gen.emit(fmt.Sprintf("func New%s(init ...interface{}) %s {\n", name, name))
	gen.emit("\tif len(init) == 1 {\n")
	gen.emit("\t\tswitch v := init[0].(type) {\n")
	gen.emit(fmt.Sprintf("\t\tcase %s:\n", name))
	gen.emit("\t\t\treturn v\n")
	gen.emit("\t\tcase int:\n")
	gen.emit(fmt.Sprintf("\t\t\treturn %s(v)\n", name))
	gen.emit("\t\tcase int32:\n")
	gen.emit(fmt.Sprintf("\t\t\treturn %s(v)\n", name))
	gen.emit("\t\tcase string:\n")
	gen.emit(fmt.Sprintf("\t\t\tfor i, s := range names%s {\n", name))
	gen.emit("\t\t\t\tif s == v {\n")
	gen.emit(fmt.Sprintf("\t\t\t\t\treturn %s(i)\n", name))
	gen.emit("\t\t\t\t}\n")
	gen.emit("\t\t\t}\n")
	gen.emit("\t\tdefault:\n")
	gen.emit(fmt.Sprintf("\t\t\tpanic(\"Bad init value for %s enum\")\n", name))
	gen.emit("\t\t}\n")
	gen.emit("\t}\n")
	gen.emit(fmt.Sprintf("\treturn %s(0) //default to the first enum value\n", name))
	gen.emit("}\n\n")
	gen.emit("// String - return a string representation of the enum\n")
	gen.emit(fmt.Sprintf("func (e %s) String() string {\n", name))
	gen.emit(fmt.Sprintf("\treturn names%s[e]\n", name))
	gen.emit("}\n\n")
	gen.emit("// SymbolSet - return an array of all valid string representations (symbols) of the enum\n")
	gen.emit(fmt.Sprintf("func (e %s) SymbolSet() []string {\n", name))
	gen.emit(fmt.Sprintf("\treturn names%s\n", name))
	gen.emit("}\n\n")
	gen.emit(fmt.Sprintf("// MarshalJSON is defined for proper JSON encoding of a %s\n", name))
	gen.emit(fmt.Sprintf("func (e %s) MarshalJSON() ([]byte, error) {\n", name))
	gen.emit("\treturn json.Marshal(e.String())\n")
	gen.emit("}\n\n")
	gen.emit(fmt.Sprintf("// UnmarshalJSON is defined for proper JSON decoding of a %s\n", name))
	gen.emit(fmt.Sprintf("func (e *%s) UnmarshalJSON(b []byte) error {\n", name))
	gen.emit("\tvar j string\n")
	gen.emit("\terr := json.Unmarshal(b, &j)\n")
	gen.emit("\tif err == nil {\n")
	gen.emit("\t\ts := string(j)\n")
	gen.emit(fmt.Sprintf("\t\tfor v, s2 := range names%s {\n", name))
	gen.emit("\t\t\tif s == s2 {\n")
	gen.emit(fmt.Sprintf("\t\t\t\t*e = %s(v)\n", name))
	gen.emit("\t\t\t\treturn nil\n")
	gen.emit("\t\t\t}\n")
	gen.emit("\t\t}\n")
	gen.emit(fmt.Sprintf("\t\terr = fmt.Errorf(\"Bad enum symbol for type %s: %%s\", s)\n", name))
	gen.emit("\t}\n")
	gen.emit("\treturn err\n")
	gen.emit("}\n")
}

func (gen *modelGenerator) emitStructFields(fields []*rdl.StructFieldDef, name rdl.TypeName) {
	gen.emit(fmt.Sprintf("type %s struct {\n", name))
	if fields != nil {
		fnames := make([]string, 0, len(fields))
		ftypes := make([]string, 0, len(fields))
		nameWidth := 0
		typeWidth := 0
		hasComment := false
		for _, f := range fields {
			fname := capitalize(string(f.Name))
			fnames = append(fnames, fname)
			flen := len(fname)
			if flen > nameWidth {
				nameWidth = flen
			}
			optional := f.Optional
			ftype := goType(gen.registry, f.Type, optional, f.Items, f.Keys, gen.precise, true)
			ftypes = append(ftypes, ftype)
			tlen := len(ftype)
			if tlen > typeWidth {
				typeWidth = tlen
			}
			if f.Comment != "" {
				hasComment = true
			}
		}
		i := 0
		for _, f := range fields {
			fname := fnames[i]
			ftype := ftypes[i]
			if !hasComment {
				fname = leftJustified(fname, nameWidth+1)
				ftype = leftJustified(ftype, typeWidth+1)
			} else {
				fname = fname + " "
				ftype = ftype + " "
			}
			option := ""
			yamlOption := ""
			optional := ""
			if f.Optional {
				// if the type specified is plain string
				// then we're not going to include omitempty
				// since we want to send empty strings to the
				// server to disable the setting
				if strings.ToLower(string(f.Type)) != "string" {
					option = ",omitempty"
				}
				yamlOption = " yaml:\",omitempty\""
				optional = " rdl:\"optional\""
			} else if f.Default != nil {
				defaultVal := fmt.Sprintf("%v", f.Default)
				optional = fmt.Sprintf(" rdl:\"default=%s\"", defaultVal)
				//omit empty only if the default value is the same as the zero value
				v := reflect.ValueOf(f.Default)
				if v.Interface() == reflect.Zero(v.Type()).Interface() {
					//if f.Default.IsZero() {
					option = ",omitempty"
					yamlOption = " yaml:\",omitempty\""
				}
			}
			jsonName := string(f.Name)
			if ext, ok := f.Annotations["x_json_name"]; ok {
				jsonName = ext
			}
			fanno := "`json:\"" + jsonName + option + "\"" + optional + yamlOption + "`"
			if f.Comment != "" {
				gen.emit("\n" + genutil.FormatBlock(f.Comment, 0, 72, "\t// "))
			}
			gen.emit(fmt.Sprintf("\t%s%s%s\n", fname, ftype, fanno))
			i++
		}
		gen.emit("}\n")
	}
}

func goFmt(filename string) error {
	return exec.Command("go", "fmt", filename).Run()
}

func GenerationHeader(banner string) string {
	// Matches the auto-generated code header structure defined at
	// https://github.com/golang/go/issues/13560#issuecomment-288457920
	return fmt.Sprintf("// Code generated by %s DO NOT EDIT.\n", banner)
}

func GenerationPackage(schema *rdl.Schema, ns string) string {
	pkg := "main"
	if ns != "" {
		pkg = ns
	} else if schema.Name != "" {
		pkg = strings.ToLower(string(schema.Name))
	}
	return pkg
}

func formatComment(s string, leftCol int, rightCol int) string {
	return genutil.FormatBlock(s, leftCol, rightCol, "// ")
}

func capitalize(text string) string {
	return strings.ToUpper(text[0:1]) + text[1:]
}

func leftJustified(text string, width int) string {
	return text + genutil.Spaces(width-len(text))
}
