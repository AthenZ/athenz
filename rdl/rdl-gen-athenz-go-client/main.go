// Copyright The Athenz Authors
// https://github.com/ardielle modified to generate go client code for Athenz Clients
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"text/template"

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

func main() {
	banner := "rdl (development version)"
	if rdl.Version != "" {
		banner = fmt.Sprintf("rdl %s", rdl.Version)
	}

	pOutdir := flag.String("o", ".", "Output directory")
	pSchemaFile := flag.String("s", "", "RDL source file")
	flag.Parse()

	schema, err := rdl.ParseRDLFile(*pSchemaFile, false, false, false)
	if err == nil {
		GenerateAthenzGoClient(banner, schema, *pOutdir, "")
		os.Exit(0)
	}
	fmt.Fprintf(os.Stderr, "*** %v\n", err)
	os.Exit(1)
}

func GenerateAthenzGoClient(banner string, schema *rdl.Schema, outdir string, ns string) error {

	name := strings.ToLower(string(schema.Name))
	if outdir == "" {
		outdir = "."
		name = name + "_client.go"
	} else if strings.HasSuffix(outdir, ".go") {
		name = filepath.Base(outdir)
		outdir = filepath.Dir(outdir)
	} else {
		name = name + "_client.go"
	}
	filePath := outdir + "/" + name
	out, file, _, err := outputWriter(filePath, "", ".go")
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
	gen := &clientGenerator{
		registry: rdl.NewTypeRegistry(schema),
		schema:   schema,
		name:     capitalize(string(schema.Name)),
		writer:   out,
		banner:   banner,
		precise:  true,
		ns:       ns,
		librdl:   RdlGoImport,
	}
	gen.emitClient()
	out.Flush()
	return gen.err
}

const clientTemplate = `{{header}}

package {{package}}

import (
	"bytes"
	"encoding/json"
	"fmt"
	rdl "{{rdlruntime}}"
	"io"
	"io/ioutil"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"time"
)

var _ = json.Marshal
var _ = fmt.Printf
var _ = rdl.BaseTypeAny
var _ = ioutil.NopCloser

type {{client}} struct {
	URL             string
	Transport       http.RoundTripper
	CredsHeaders    map[string]string
	Timeout         time.Duration
	DisableRedirect bool
}

// NewClient creates and returns a new HTTP client object for the {{.Name}} service
func NewClient(url string, transport http.RoundTripper) {{client}} {
	return {{client}}{url, transport, make(map[string]string), 0, false}
}

// AddCredentials adds the credentials to the client for subsequent requests.
func (client *{{client}}) AddCredentials(header string, token string) {
	client.CredsHeaders[header] = token
}

func (client {{client}}) getClient() *http.Client {
	var c *http.Client
	if client.Transport != nil {
		c = &http.Client{Transport: client.Transport}
	} else {
		c = &http.Client{}
	}
	if client.DisableRedirect {
		c.CheckRedirect = func(req *http.Request, via []*http.Request) error {
			return http.ErrUseLastResponse
		}
	}
	if client.Timeout > 0 {
		c.Timeout = client.Timeout
	}
	return c
}

func (client {{client}}) addAuthHeader(req *http.Request) {
	if len(client.CredsHeaders) == 0 {
		return
	}
	for key, value := range client.CredsHeaders {
		if strings.HasPrefix(key, "Cookie.") {
			req.Header.Add("Cookie", (key)[7:]+"="+value)
		} else {
			req.Header.Add(key, value)
		}
	}
}

func (client {{client}}) httpGet(url string, headers map[string]string) (*http.Response, error) {
	hclient := client.getClient()
	req, err := http.NewRequest("GET", url, nil)
	if err != nil {
		return nil, err
	}
	client.addAuthHeader(req)
	if headers != nil {
		for k, v := range headers {
			req.Header.Add(k, v)
		}
	}
	return hclient.Do(req)
}

func (client {{client}}) httpDelete(url string, headers map[string]string) (*http.Response, error) {
	hclient := client.getClient()
	req, err := http.NewRequest("DELETE", url, nil)
	if err != nil {
		return nil, err
	}
	client.addAuthHeader(req)
	if headers != nil {
		for k, v := range headers {
			req.Header.Add(k, v)
		}
	}
	return hclient.Do(req)
}

func (client {{client}}) httpPut(url string, headers map[string]string, body []byte) (*http.Response, error) {
	var contentReader io.Reader
	if body != nil {
		contentReader = bytes.NewReader(body)
	}
	hclient := client.getClient()
	req, err := http.NewRequest("PUT", url, contentReader)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-type", "application/json")
	client.addAuthHeader(req)
	if headers != nil {
		for k, v := range headers {
			req.Header.Add(k, v)
		}
	}
	return hclient.Do(req)
}

func (client {{client}}) httpPostWithContentType(url string, headers map[string]string, body []byte, contentType string) (*http.Response, error) {
	var contentReader io.Reader
	if body != nil {
		contentReader = bytes.NewReader(body)
	}
	hclient := client.getClient()
	req, err := http.NewRequest("POST", url, contentReader)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-type", contentType)
	client.addAuthHeader(req)
	if headers != nil {
		for k, v := range headers {
			req.Header.Add(k, v)
		}
	}
	return hclient.Do(req)
}

func (client {{client}}) httpPost(url string, headers map[string]string, body []byte) (*http.Response, error) {
	return client.httpPostWithContentType(url, headers, body, "application/json")
}

func (client {{client}}) httpPatch(url string, headers map[string]string, body []byte) (*http.Response, error) {
	var contentReader io.Reader
	if body != nil {
		contentReader = bytes.NewReader(body)
	}
	hclient := client.getClient()
	req, err := http.NewRequest("PATCH", url, contentReader)
	if err != nil {
		return nil, err
	}
	req.Header.Add("Content-type", "application/json")
	client.addAuthHeader(req)
	if headers != nil {
		for k, v := range headers {
			req.Header.Add(k, v)
		}
	}
	return hclient.Do(req)
}

func (client {{client}}) httpOptions(url string, headers map[string]string, body []byte) (*http.Response, error) {
	var contentReader io.Reader = nil
	if body != nil {
		contentReader = bytes.NewReader(body)
	}
	hclient := client.getClient()
	req, err := http.NewRequest("OPTIONS", url, contentReader)
	if err != nil {
		return nil, err
	}
	if contentReader != nil {
		req.Header.Add("Content-type", "application/json")
	}
	client.addAuthHeader(req)
	if headers != nil {
		for k, v := range headers {
			req.Header.Add(k, v)
		}
	}
	return hclient.Do(req)
}

func encodeStringParam(name string, val string, def string) string {
	if val == def {
		return ""
	}
	return "&" + name + "=" + url.QueryEscape(val)
}
func encodeBoolParam(name string, b bool, def bool) string {
	if b == def {
		return ""
	}
	return fmt.Sprintf("&%s=%v", name, b)
}
func encodeInt8Param(name string, i int8, def int8) string {
	if i == def {
		return ""
	}
	return "&" + name + "=" + strconv.Itoa(int(i))
}
func encodeInt16Param(name string, i int16, def int16) string {
	if i == def {
		return ""
	}
	return "&" + name + "=" + strconv.Itoa(int(i))
}
func encodeInt32Param(name string, i int32, def int32) string {
	if i == def {
		return ""
	}
	return "&" + name + "=" + strconv.Itoa(int(i))
}
func encodeInt64Param(name string, i int64, def int64) string {
	if i == def {
		return ""
	}
	return "&" + name + "=" + strconv.FormatInt(i, 10)
}
func encodeTimestampParam(name string, i rdl.Timestamp, def rdl.Timestamp) string {
	if i == def {
		return ""
	}
	return "&" + name + "=" + url.QueryEscape(i.String())
}
func encodeUUIDParam(name string, i rdl.UUID, def rdl.UUID) string {
	if i.Equal(def) {
		return ""
	}
	return "&" + name + "=" + i.String()
}
func encodeFloat32Param(name string, i float32, def float32) string {
	if i == def {
		return ""
	}
	return "&" + name + "=" + strconv.FormatFloat(float64(i), 'g', -1, 32)
}
func encodeFloat64Param(name string, i float64, def float64) string {
	if i == def {
		return ""
	}
	return "&" + name + "=" + strconv.FormatFloat(i, 'g', -1, 64)
}
func encodeOptionalEnumParam(name string, e interface{}) string {
	if e == nil {
		return "\"\""
	}
	return fmt.Sprintf("&%s=%v", name, e)
}
func encodeOptionalBoolParam(name string, b *bool) string {
	if b == nil {
		return ""
	}
	return fmt.Sprintf("&%s=%v", name, *b)
}
func encodeOptionalInt32Param(name string, i *int32) string {
	if i == nil {
		return ""
	}
	return "&" + name + "=" + strconv.Itoa(int(*i))
}
func encodeOptionalInt64Param(name string, i *int64) string {
	if i == nil {
		return ""
	}
	return "&" + name + "=" + strconv.Itoa(int(*i))
}
func encodeOptionalTimestampParam(name string, i *rdl.Timestamp) string {
	if i == nil {
		return ""
	}
	return "&" + name + "=" + url.QueryEscape(i.String())
}
func encodeOptionalUUIDParam(name string, i *rdl.UUID) string {
	if i == nil {
		return ""
	}
	return "&" + name + "=" + i.String()
}
func encodeParams(objs ...string) string {
	s := strings.Join(objs, "")
	if s == "" {
		return s
	}
	return "?" + s[1:]
}
{{range .Resources}}
func (client {{client}}) {{method_sig .}} {
{{method_body .}}
}
{{end}}`

func (gen *clientGenerator) emitClient() error {
	commentFun := func(s string) string {
		return formatComment(s, 0)
	}
	basenameFunc := func(s string) string {
		i := strings.LastIndex(s, ".")
		if i >= 0 {
			s = s[i+1:]
		}
		return s
	}
	fieldFun := func(f rdl.StructFieldDef) string {
		optional := f.Optional
		fType := GoType(gen.registry, f.Type, optional, f.Items, f.Keys, gen.precise, true, "")
		fName := capitalize(string(f.Name))
		option := ""
		yamlOption := ""
		if optional {
			option = ",omitempty"
			yamlOption = " yaml:\",omitempty\""

		}
		jsonName := string(f.Name)
		if ext, ok := f.Annotations["x_json_name"]; ok {
			jsonName = ext
		}
		fAnno := "`json:\"" + jsonName + option + "\"" + yamlOption + "`"
		return fmt.Sprintf("%s %s%s", fName, fType, fAnno)
	}
	funcMap := template.FuncMap{
		"rdlruntime":  func() string { return gen.librdl },
		"header":      func() string { return generationHeader(gen.banner) },
		"package":     func() string { return generationPackage(gen.schema, gen.ns) },
		"field":       fieldFun,
		"flattened":   func(t *rdl.Type) []*rdl.StructFieldDef { return flattenedFields(gen.registry, t) },
		"typeRef":     func(t *rdl.Type) string { return makeTypeRef(gen.registry, t, gen.precise) },
		"basename":    basenameFunc,
		"comment":     commentFun,
		"method_sig":  func(r *rdl.Resource) string { return goMethodSignature(gen.registry, r, gen.precise) },
		"method_body": func(r *rdl.Resource) string { return goMethodBody(gen.registry, r, gen.precise) },
		"client":      func() string { return gen.name + "Client" },
	}
	t := template.Must(template.New("FOO").Funcs(funcMap).Parse(clientTemplate))
	return t.Execute(gen.writer, gen.schema)
}

func goMethodSignature(reg rdl.TypeRegistry, r *rdl.Resource, precise bool) string {
	noContent := r.Expected == "NO_CONTENT" && r.Alternatives == nil
	returnSpec := "error"
	//fixme: no content *with* output headers
	if !noContent {
		gtype := GoType(reg, r.Type, false, "", "", precise, true, "")
		returnSpec = "(" + gtype
		if r.Outputs != nil {
			for _, o := range r.Outputs {
				otype := GoType(reg, o.Type, false, "", "", precise, true, "")
				returnSpec += ", " + otype
			}
		}
		returnSpec += ", error)"
	}
	methName, params := goMethodName(reg, r, precise)
	return capitalize(methName) + "(" + strings.Join(params, ", ") + ") " + returnSpec
}

func goLiteral(lit interface{}, baseType string) string {
	if lit == nil {
		if baseType == "Bool" {
			return "false"
		} else if baseType == "Int32" || baseType == "Int64" || baseType == "Int16" || baseType == "Int8" {
			return "0"
		} else if baseType == "Float64" || baseType == "Float32" {
			return "0.0"
		} else {
			return "\"\""
		}
	}
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

func explodeURL(reg rdl.TypeRegistry, r *rdl.Resource) string {
	path := r.Path
	params := ""
	delim := ""
	for _, v := range r.Inputs {
		k := v.Name
		gk := goName(string(k))
		if v.PathParam {
			//
			if v.Type == "String" {
				path = strings.Replace(path, "{"+string(k)+"}", "\" + "+gk+" + \"", -1)
			} else {
				path = strings.Replace(path, "{"+string(k)+"}", "\" + fmt.Sprint("+gk+") + \"", -1)
			}
		} else if v.QueryParam != "" {
			qp := v.QueryParam
			item := ""
			if reg.IsArrayTypeName(v.Type) {
				item = "encodeListParam(\"" + qp + "\"," + gk + ")"
			} else {
				baseType := reg.BaseTypeName(v.Type)
				if v.Optional && baseType != "String" {
					item = "encodeOptional" + string(baseType) + "Param(\"" + qp + "\", " + gk + ")"
				} else {
					def := goLiteral(v.Default, string(baseType))
					if baseType == "Enum" {
						def = "\"" + def + "\""
						item = "encodeStringParam(\"" + qp + "\", " + gk + ".String(), " + def + ")"
					} else {
						item = "encode" + string(baseType) + "Param(\"" + qp + "\", " + strings.ToLower(string(baseType)) + "(" + gk + "), " + def + ")"
					}
				}
			}
			params += delim + item
			delim = ", "
		}
	}
	path = "\"" + path
	if strings.HasSuffix(path, " + \"") {
		path = path[0 : len(path)-4]
	} else {
		path += "\""
	}
	if params != "" {
		path = path + " + encodeParams(" + params + ")"
	}
	return path
}

func goMethodBody(reg rdl.TypeRegistry, r *rdl.Resource, precise bool) string {
	rtype := GoType(reg, r.Type, false, "", "", precise, true, "")
	dataDef := fmt.Sprintf("var data %s", rtype)
	errorReturn := "return data, err"
	dataReturn := "return data, nil"
	noContent := r.Expected == "NO_CONTENT" && r.Alternatives == nil
	if noContent {
		errorReturn = "return err"
		dataReturn = "return nil"
		dataDef = ""
	}
	if r.Outputs != nil {
		dret := "return data"
		eret := "return nil"
		for _, o := range r.Outputs {
			dret += ", " + goName(string(o.Name))
			eret += ", \"\""
		}
		dret += ", nil"
		eret += ", err"
		dataReturn = dret
		errorReturn = eret
	}
	headers := map[string]*rdl.ResourceInput{}
	for _, in := range r.Inputs {
		if in.Header != "" {
			headers[in.Header] = in
		}
	}
	s := ""
	if dataDef != "" {
		s += "\t" + dataDef + "\n"
	}
	httpArg := "url, nil"
	if len(headers) > 0 {
		//sort the header names so we have a defined order every time
		headerNames := make([]string, 0, len(headers))
		for headerName := range headers {
			headerNames = append(headerNames, headerName)
		}
		sort.Strings(headerNames)
		httpArg = "url, headers"
		s += "\theaders := map[string]string{\n"
		for _, k := range headerNames {
			v := headers[k]
			if v.Type == "Bool" {
				s += fmt.Sprintf("\t\t%q: strconv.FormatBool(*%s),\n", k, v.Name)
			} else {
				s += fmt.Sprintf("\t\t%q: %s,\n", k, v.Name)
			}
		}
		s += "\t}\n"
	}
	url := explodeURL(reg, r)
	s += "\turl := client.URL + " + url + "\n"
	method := capitalize(strings.ToLower(r.Method))
	assign := ":="
	switch method {
	case "Get", "Delete":
		s += "\tresp, err := client.http" + method + "(" + httpArg + ")\n"
	case "Put", "Post", "Patch":
		bodyParam := ""
		for _, in := range r.Inputs {
			name := in.Name
			if !in.PathParam && in.QueryParam == "" && in.Header == "" {
				bodyParam = string(name)
				break
			}
		}
		if bodyParam == "" {
			s += "\tvar contentBytes []byte\n"
			s += "\tresp, err := client.http" + method + "(" + httpArg + ", contentBytes)\n"
		} else if len(r.Consumes) > 0 {
			s += "\tcontentBytes := []byte(" + bodyParam + ")\n"
			s += "\tresp, err := client.http" + method + "WithContentType(" + httpArg + ", contentBytes, \"" + r.Consumes[0] + "\")\n"
		} else {
			s += "\tcontentBytes, err := json.Marshal(" + bodyParam + ")\n"
			s += "\tif err != nil {\n\t\t" + errorReturn + "\n\t}\n"
			s += "\tresp, err := client.http" + method + "(" + httpArg + ", contentBytes)\n"
		}
		assign = "="
	case "Options":
		bodyParam := "?"
		for _, in := range r.Inputs {
			name := in.Name
			if !in.PathParam && in.QueryParam == "" && in.Header == "" {
				bodyParam = string(name)
				break
			}
		}
		if bodyParam != "?" {
			s += "\tcontentBytes, err := json.Marshal(" + bodyParam + ")\n"
			s += "\tif err != nil {\n\t\t" + errorReturn + "\n\t}\n"
			s += "\tresp, err := client.http" + method + "(" + httpArg + ", contentBytes)\n"
			assign = "="
		} else {
			s += "\tresp, err := client.http" + method + "(" + httpArg + ", nil)\n"
		}
	}
	s += "\tif err != nil {\n\t\t" + errorReturn + "\n\t}\n"
	s += "\tdefer resp.Body.Close()\n"
	s += "\tswitch resp.StatusCode {\n"
	//loop for all expected results
	var expected []string
	expected = append(expected, rdl.StatusCode(r.Expected))
	couldBeNoContent := "NO_CONTENT" == r.Expected
	couldBeNotModified := "NOT_MODIFIED" == r.Expected
	couldBeRedirect := "FOUND" == r.Expected
	for _, e := range r.Alternatives {
		if "NO_CONTENT" == e {
			couldBeNoContent = true
		}
		if "NOT_MODIFIED" == e {
			couldBeNotModified = true
		}
		if "FOUND" == e {
			couldBeRedirect = true
		}
		expected = append(expected, rdl.StatusCode(e))
	}
	s += "\tcase " + strings.Join(expected, ", ") + ":\n"
	if couldBeNoContent || couldBeNotModified || couldBeRedirect {
		if !noContent {
			tmp := ""
			if couldBeNoContent {
				tmp = "204 != resp.StatusCode"
			}
			if couldBeNotModified {
				if tmp != "" {
					tmp += " || "
				}
				tmp += "304 != resp.StatusCode"
			}
			if couldBeRedirect {
				if tmp != "" {
					tmp += " || "
				}
				tmp += "302 != resp.StatusCode"
			}
			s += "\t\tif " + tmp + " {\n"
			s += "\t\t\terr = json.NewDecoder(resp.Body).Decode(&data)\n"
			s += "\t\t\tif err != nil {\n\t\t\t\t" + errorReturn + "\n\t\t\t}\n"
			s += "\t\t}\n"
		}
	} else {
		s += "\t\terr = json.NewDecoder(resp.Body).Decode(&data)\n"
		s += "\t\tif err != nil {\n\t\t\t" + errorReturn + "\n\t\t}\n"
	}
	//here, define the output headers
	if r.Outputs != nil {
		for _, o := range r.Outputs {
			otype := GoType(reg, o.Type, false, "", "", precise, true, "")
			header := fmt.Sprintf("resp.Header.Get(rdl.FoldHttpHeaderName(%q))", o.Header)
			if otype != "string" {
				header = otype + "(" + header + ")"
			}
			s += "\t\t" + goName(string(o.Name)) + " := " + header + "\n"
		}
	}
	s += "\t\t" + dataReturn + "\n"
	//end loop
	s += "\tdefault:\n"
	s += "\t\tvar errobj rdl.ResourceError\n"
	s += "\t\tcontentBytes, err " + assign + " io.ReadAll(resp.Body)\n"
	s += "\t\tif err != nil {\n\t\t\t" + errorReturn + "\n\t\t}\n"
	s += "\t\tjson.Unmarshal(contentBytes, &errobj)\n"
	s += "\t\tif errobj.Code == 0 {\n"
	s += "\t\t\terrobj.Code = resp.StatusCode\n"
	s += "\t\t}\n"
	s += "\t\tif errobj.Message == \"\" {\n"
	s += "\t\t\terrobj.Message = string(contentBytes)\n"
	s += "\t\t}\n"
	s += "\t\t" + errorReturn + "obj\n"
	s += "\t}"

	return s
}

func makeTypeRef(reg rdl.TypeRegistry, t *rdl.Type, precise bool) string {
	switch t.Variant {
	case rdl.TypeVariantAliasTypeDef:
		typedef := t.AliasTypeDef
		return GoType(reg, typedef.Type, false, "", "", precise, true, "")
	case rdl.TypeVariantStringTypeDef:
		typedef := t.StringTypeDef
		return GoType(reg, typedef.Type, false, "", "", precise, true, "")
	case rdl.TypeVariantNumberTypeDef:
		typedef := t.NumberTypeDef
		return GoType(reg, typedef.Type, false, "", "", precise, true, "")
	case rdl.TypeVariantArrayTypeDef:
		typedef := t.ArrayTypeDef
		return GoType(reg, typedef.Type, false, typedef.Items, "", precise, true, "")
	case rdl.TypeVariantMapTypeDef:
		typedef := t.MapTypeDef
		return GoType(reg, typedef.Type, false, typedef.Items, typedef.Keys, precise, true, "")
	case rdl.TypeVariantStructTypeDef:
		typedef := t.StructTypeDef
		return GoType(reg, typedef.Type, false, "", "", precise, true, "")
	case rdl.TypeVariantEnumTypeDef:
		typedef := t.EnumTypeDef
		return GoType(reg, typedef.Type, false, "", "", precise, true, "")
	case rdl.TypeVariantUnionTypeDef:
		return "interface{}" //! FIX
	}
	return "?" //never happens
}

func goMethodName(reg rdl.TypeRegistry, r *rdl.Resource, precise bool) (string, []string) {
	return goMethodName2(reg, r, precise, "")
}

func goMethodName2(reg rdl.TypeRegistry, r *rdl.Resource, precise bool, packageName string) (string, []string) {
	var params []string
	bodyType := string(SafeTypeVarName(r.Type))
	for _, v := range r.Inputs {
		if v.Context != "" { //legacy field, to be removed
			continue
		}
		k := v.Name
		if v.QueryParam == "" && !v.PathParam && v.Header == "" {
			bodyType = string(v.Type)
		}
		optional := false
		if v.Optional {
			optional = true
		}
		params = append(params, goName(string(k))+" "+GoType(reg, v.Type, optional, "", "", precise, true, packageName))
	}
	meth := string(r.Name)
	if meth == "" {
		meth = strings.ToLower(r.Method) + bodyType
	} else {
		meth = uncapitalize(meth)
	}
	return meth, params
}

func goName(name string) string {
	switch name {
	case "type", "default": //other reserved words
		return "_" + name
	default:
		return name
	}
}
