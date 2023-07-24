// Copyright The Athenz Authors
//           Modified https://github.com/ardielle to generate server code for Athenz Server components
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package main

import (
	"bufio"
	"flag"
	"fmt"
	"github.com/ardielle/ardielle-go/rdl"
	"log"
	"os"
	"sort"
	"strings"
	"text/template"
)

type javaServerGenerator struct {
	registry rdl.TypeRegistry
	schema   *rdl.Schema
	name     string
	writer   *bufio.Writer
	err      error
	banner   string
	ns       string
	base     string
}

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
		GenerateZMSJavaServer(banner, schema, *pOutdir, "", *pBase)
		os.Exit(0)
	}
	fmt.Fprintf(os.Stderr, "*** %v\n", err)
	os.Exit(1)
}

// GenerateJavaServer generates the server code for the RDL-defined service
func GenerateZMSJavaServer(banner string, schema *rdl.Schema, outdir string, ns string, base string) error {
	fmt.Fprintln(os.Stderr, "Starting ZMS Server code generation...")
	reg := rdl.NewTypeRegistry(schema)
	packageDir, err := javaGenerationDir(outdir, schema, ns)
	if err != nil {
		return err
	}
	cName := capitalize(string(schema.Name))

	//FooHandler interface
	out, file, _, err := outputWriter(packageDir, cName, "Handler.java")
	if err != nil {
		return err
	}
	gen := &javaServerGenerator{reg, schema, cName, out, nil, banner, ns, base}
	gen.processTemplate(javaServerHandlerTemplate)
	out.Flush()
	file.Close()

	//ResourceContext interface
	s := "ResourceContext"
	out, file, _, err = outputWriter(packageDir, s, ".java")
	if err != nil {
		return err
	}
	gen = &javaServerGenerator{reg, schema, cName, out, nil, banner, ns, base}
	gen.processTemplate(javaServerContextTemplate)
	out.Flush()
	file.Close()
	if gen.err != nil {
		return gen.err
	}

	//FooResources Jax-RS glue
	out, file, _, err = outputWriter(packageDir, cName, "Resources.java")
	if err != nil {
		return err
	}
	gen = &javaServerGenerator{reg, schema, cName, out, nil, banner, ns, base}
	gen.processTemplate(javaServerTemplate)
	out.Flush()
	file.Close()
	if gen.err != nil {
		return gen.err
	}

	//Note: to enable jackson's pretty printer:
	//import com.fasterxml.jackson.jaxrs.annotation.JacksonFeatures;
	//import com.fasterxml.jackson.databind.SerializationFeature;
	//for each resource, add this annotation:
	//   @JacksonFeatures(serializationEnable =  { SerializationFeature.INDENT_OUTPUT })

	//ResourceException - the throawable wrapper for alternate return types
	s = "ResourceException"
	out, file, _, err = outputWriter(packageDir, s, ".java")
	if err != nil {
		return err
	}
	err = javaGenerateResourceException(banner, schema, out, ns)
	out.Flush()
	file.Close()
	if err != nil {
		return err
	}

	//ResourceError - the default data object for an error
	s = "ResourceError"
	out, file, _, err = outputWriter(packageDir, s, ".java")
	if err != nil {
		return err
	}
	err = javaGenerateResourceError(banner, schema, out, ns)
	out.Flush()
	file.Close()
	return err
}

func (gen *javaServerGenerator) resultSignature(r *rdl.Resource) string {
	vName := string(safeTypeVarName(r.Type)) + "Object"
	s := javaType(gen.registry, r.Type, false, "", "") + " " + vName
	for _, out := range r.Outputs {
		s += ", " + javaType(gen.registry, out.Type, false, "", "") + " " + javaName(out.Name)
	}
	return s
}

func (gen *javaServerGenerator) resultArgs(r *rdl.Resource) string {
	vName := string(safeTypeVarName(r.Type)) + "Object"
	for _, out := range r.Outputs {
		vName += ", " + javaName(out.Name)
	}
	return vName
}

func (gen *javaServerGenerator) makePathParamsKey(r *rdl.Resource) string {
	s := ""
	if len(r.Outputs) > 0 {
		for _, in := range r.Inputs {
			if in.PathParam {
				if s == "" && gen.registry.IsStringTypeName(in.Type) {
					s = javaName(in.Name)
				} else {
					s += " + \".\" + " + javaName(in.Name)
				}
			}
		}
	}
	if s == "" {
		s = "\"" + r.Path + "\"" //If there are no input params, make the path as the key
	}
	return s
}

func (gen *javaServerGenerator) makePathParamsDecls(r *rdl.Resource) string {
	s := ""
	if len(r.Outputs) > 0 {
		for _, in := range r.Inputs {
			if in.PathParam {
				jtype := javaType(gen.registry, in.Type, false, "", "")
				s += "\n    private " + jtype + " " + javaName(in.Name) + ";"
			}
		}
	}
	return s
}

func (gen *javaServerGenerator) makePathParamsSig(r *rdl.Resource) []string {
	s := make([]string, 0)
	if len(r.Outputs) > 0 {
		for _, in := range r.Inputs {
			if in.PathParam {
				jtype := javaType(gen.registry, in.Type, false, "", "")
				s = append(s, jtype+" "+javaName(in.Name))
			}
		}
	}
	return s
}

func (gen *javaServerGenerator) makePathParamsArgs(r *rdl.Resource) []string {
	s := make([]string, 0)
	if len(r.Outputs) > 0 {
		for _, in := range r.Inputs {
			if in.PathParam {
				s = append(s, javaName(in.Name))
			}
		}
	}
	return s
}

func (gen *javaServerGenerator) makePathParamsAssign(r *rdl.Resource) string {
	s := ""
	if len(r.Outputs) > 0 {
		for _, in := range r.Inputs {
			if in.PathParam {
				jname := javaName(in.Name)
				s += "\n        this." + jname + " = " + jname + ";"
			}
		}
	}
	return s
}

func (gen *javaServerGenerator) makeHeaderParams(r *rdl.Resource) []string {
	s := make([]string, 0)
	if len(r.Outputs) > 0 {
		for _, out := range r.Outputs {
			s = append(s, javaName(out.Name))
		}
	}
	return s
}

func (gen *javaServerGenerator) makeHeaderParamsSig(r *rdl.Resource) []string {
	s := make([]string, 0)
	if len(r.Outputs) > 0 {
		for _, out := range r.Outputs {
			jtype := javaType(gen.registry, out.Type, false, "", "")
			s = append(s, jtype+" "+javaName(out.Name))
		}
	}
	return s
}

func (gen *javaServerGenerator) makeHeaderAssign(r *rdl.Resource) string {
	s := ""
	if len(r.Outputs) > 0 {
		for _, out := range r.Outputs {
			jname := javaName(out.Name)
			s += fmt.Sprintf("\n            .header(%q, %s)", out.Header, jname)
		}
	}
	return s
}

const javaServerHandlerTemplate = `{{header}}
{{package}}
import com.yahoo.rdl.*;
import jakarta.ws.rs.core.Response;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;

//
// {{cName}}Handler is the interface that the service implementation must implement
//
public interface {{cName}}Handler {{openBrace}} {{range .Resources}}
    {{methodSig .}};{{end}}
    ResourceContext newResourceContext(ServletContext servletContext, HttpServletRequest request, HttpServletResponse response, String apiName);
    void recordMetrics(ResourceContext ctx, int httpStatus);
    void publishChangeMessage(ResourceContext ctx, int httpStatus);
}
`

const javaServerContextTemplate = `{{header}}
{{package}}
import com.yahoo.athenz.common.messaging.DomainChangeMessage;

import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import java.util.List;

//
// ResourceContext
//
public interface ResourceContext {
    ServletContext servletContext();
    HttpServletRequest request();
    HttpServletResponse response();
    String getApiName();
    String getHttpMethod();
    void authenticate();
    void authorize(String action, String resource, String trustedDomain);
    void addDomainChangeMessage(DomainChangeMessage domainChangeMsg);
    List<DomainChangeMessage> getDomainChangeMessages();
}
`

const javaServerTemplate = `{{header}}
{{package}}
import com.yahoo.rdl.*;
import jakarta.ws.rs.*;
import jakarta.ws.rs.core.*;
import jakarta.servlet.ServletContext;
import jakarta.servlet.http.HttpServletRequest;
import jakarta.servlet.http.HttpServletResponse;
import jakarta.inject.Inject;
import io.swagger.v3.oas.annotations.Operation;
import io.swagger.v3.oas.annotations.Parameter;

@Path("{{rootPath}}")
public class {{cName}}Resources {
{{range .Resources}}
    @{{uMethod .}}
    @Path("{{methodPath .}}")
    {{handlerSig .}} {{openBrace}}
{{handlerBody .}}    }
{{end}}

    WebApplicationException typedException(int code, ResourceException e, Class<?> eClass) {
        Object data = e.getData();
        Object entity = eClass.isInstance(data) ? data : null;
        if (entity != null) {
            return new WebApplicationException(Response.status(code).entity(entity).build());
        } else {
            return new WebApplicationException(code);
        }
    }

    @Inject private {{cName}}Handler delegate;
    @Context private ServletContext servletContext;
    @Context private HttpServletRequest request;
    @Context private HttpServletResponse response;
}
`

func makeJavaTypeRef(reg rdl.TypeRegistry, t *rdl.Type) string {
	switch t.Variant {
	case rdl.TypeVariantAliasTypeDef:
		typedef := t.AliasTypeDef
		return javaType(reg, typedef.Type, false, "", "")
	case rdl.TypeVariantStringTypeDef:
		typedef := t.StringTypeDef
		return javaType(reg, typedef.Type, false, "", "")
	case rdl.TypeVariantNumberTypeDef:
		typedef := t.NumberTypeDef
		return javaType(reg, typedef.Type, false, "", "")
	case rdl.TypeVariantArrayTypeDef:
		typedef := t.ArrayTypeDef
		return javaType(reg, typedef.Type, false, typedef.Items, "")
	case rdl.TypeVariantMapTypeDef:
		typedef := t.MapTypeDef
		return javaType(reg, typedef.Type, false, typedef.Items, typedef.Keys)
	case rdl.TypeVariantStructTypeDef:
		typedef := t.StructTypeDef
		return javaType(reg, typedef.Type, false, "", "")
	case rdl.TypeVariantEnumTypeDef:
		typedef := t.EnumTypeDef
		return javaType(reg, typedef.Type, false, "", "")
	case rdl.TypeVariantUnionTypeDef:
		return "Object" //fix
	}
	return "?" //never happens
}

func (gen *javaServerGenerator) processTemplate(templateSource string) error {
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
		fType := javaType(gen.registry, f.Type, optional, f.Items, f.Keys)
		fName := capitalize(string(f.Name))
		option := ""
		if optional {
			option = ",omitempty"
		}
		fAnno := "`json:\"" + string(f.Name) + option + "\"`"
		return fmt.Sprintf("%s %s%s", fName, fType, fAnno)
	}
	funcMap := template.FuncMap{
		"header": func() string { return javaGenerationHeader(gen.banner) },
		"package": func() string {
			s := javaGenerationPackage(gen.schema, gen.ns)
			if s == "" {
				return s
			}
			return "package " + s + ";\n"
		},
		"openBrace":   func() string { return "{" },
		"field":       fieldFun,
		"flattened":   func(t *rdl.Type) []*rdl.StructFieldDef { return flattenedFields(gen.registry, t) },
		"typeRef":     func(t *rdl.Type) string { return makeJavaTypeRef(gen.registry, t) },
		"basename":    basenameFunc,
		"comment":     commentFun,
		"uMethod":     func(r *rdl.Resource) string { return strings.ToUpper(r.Method) },
		"methodSig":   func(r *rdl.Resource) string { return gen.serverMethodSignature(r) },
		"handlerSig":  func(r *rdl.Resource) string { return gen.handlerSignature(r) },
		"handlerBody": func(r *rdl.Resource) string { return gen.handlerBody(r) },
		"client":      func() string { return gen.name + "Client" },
		"server":      func() string { return gen.name + "Server" },
		"name":        func() string { return gen.name },
		"cName":       func() string { return capitalize(gen.name) },
		"methodName":  func(r *rdl.Resource) string { return strings.ToLower(r.Method) + string(r.Type) + "Handler" }, //?
		"methodPath":  func(r *rdl.Resource) string { return gen.resourcePath(r) },
		"rootPath":    func() string { return javaGenerationRootPath(gen.schema, gen.base) },
		"rName": func(r *rdl.Resource) string {
			return capitalize(strings.ToLower(r.Method)) + string(r.Type) + "Result"
		},
	}
	t := template.Must(template.New(gen.name).Funcs(funcMap).Parse(templateSource))
	return t.Execute(gen.writer, gen.schema)
}

func (gen *javaServerGenerator) resourcePath(r *rdl.Resource) string {
	path := r.Path
	i := strings.Index(path, "?")
	if i >= 0 {
		path = path[0:i]
	}
	return path
}

func (gen *javaServerGenerator) handlerBody(r *rdl.Resource) string {
	methName, _ := javaMethodName(gen.registry, r)
	noContent := r.Expected == "NO_CONTENT" && r.Alternatives == nil
	s := "        int code = ResourceException.OK;\n"
	s += "        ResourceContext context = null;\n"
	s += "        try {\n"
	s += "            context = this.delegate.newResourceContext(this.servletContext, this.request, this.response, \"" + methName + "\");\n"
	var fargs []string
	bodyName := ""
	if r.Auth != nil {
		if r.Auth.Authenticate {
			s += "            context.authenticate();\n"
		} else if r.Auth.Action != "" && r.Auth.Resource != "" {
			resource := r.Auth.Resource
			i := strings.Index(resource, "{")
			for i >= 0 {
				j := strings.Index(resource[i:], "}")
				if j < 0 {
					break
				}
				j += i
				resource = resource[0:i] + "\" + " + resource[i+1:j] + " + \"" + resource[j+1:]
				i = strings.Index(resource, "{")
			}
			resource = "\"" + resource + "\""
			s += fmt.Sprintf("            context.authorize(%q, %s, null);\n", r.Auth.Action, resource)
			//what about the domain variant?
		} else {
			log.Println("*** Badly formed auth spec in resource input:", r)
		}
	}
	for _, in := range r.Inputs {
		name := string(in.Name)
		if in.QueryParam != "" {
			fargs = append(fargs, name)
		} else if in.PathParam {
			fargs = append(fargs, name)
		} else if in.Header != "" {
			fargs = append(fargs, name)
		} else {
			bodyName = name
			fargs = append(fargs, bodyName)
		}
	}
	sargs := ""
	if len(fargs) > 0 {
		sargs = ", " + strings.Join(fargs, ", ")
	}
	if noContent {
		s += "            this.delegate." + methName + "(context" + sargs + ");\n"
	} else {
		s += "            return this.delegate." + methName + "(context" + sargs + ");\n"
	}
	s += "        } catch (ResourceException e) {\n"
	s += "            code = e.getCode();\n"
	s += "            switch (code) {\n"
	if r.Exceptions != nil && len(r.Exceptions) > 0 {
		keys := sortedExceptionKeys(r.Exceptions)
		for _, ecode := range keys {
			etype := r.Exceptions[ecode].Type
			s += "            case ResourceException." + ecode + ":\n"
			s += "                throw typedException(code, e, " + etype + ".class);\n"
		}
	}
	s += "            default:\n"
	s += "                System.err.println(\"*** Warning: undeclared exception (\" + code + \") for resource " + methName + "\");\n"
	s += "                throw typedException(code, e, ResourceError.class);\n" //? really
	s += "            }\n"
	s += "        } finally {\n"
	if r.Method == "POST" || r.Method == "PUT" || r.Method == "DELETE" {
		s += "            this.delegate.publishChangeMessage(context, code);\n"
	}
	s += "            this.delegate.recordMetrics(context, code);\n"
	s += "        }\n"
	return s
}

func (gen *javaServerGenerator) paramInit(qname string, pname string, ptype rdl.TypeRef, pdefault *interface{}) string {
	reg := gen.registry
	s := ""
	gtype := javaType(reg, ptype, false, "", "")
	switch ptype {
	case "String":
		if pdefault == nil {
			s += "\t" + pname + " := optionalStringParam(request, \"" + qname + "\", nil)\n"
		} else {
			def := fmt.Sprintf("%v", pdefault)
			s += "\tvar " + pname + "Optional " + gtype + " = " + def + "\n"
			s += "\t" + pname + " := optionalStringParam(request, \"" + qname + "\", " + pname + "Optional)\n"
		}
	case "Int32":
		if pdefault == nil {
			s += "\t" + pname + ", err := optionalInt32Param(request, \"" + qname + "\", nil)\n"
			s += "\tif err != nil {\n\t\tjsonResponse(writer, 400, err)\n\t\treturn\n\t}\n"
		} else {
			def := "0"
			switch v := (*pdefault).(type) {
			case *float64:
				def = fmt.Sprintf("%v", *v)
			default:
				panic("fix me")
			}
			s += "\t" + pname + ", err := requiredInt32Param(request, \"" + qname + "\", " + def + ")\n"
			s += "\tif err != nil {\n\t\tjsonResponse(writer, 400, err)\n\t\treturn\n\t}\n"
		}
	default:
		panic("fix me")
	}
	return s
}

func (gen *javaServerGenerator) handlerSignature(r *rdl.Resource) string {
	reg := gen.registry
	noContent := r.Expected == "NO_CONTENT" && r.Alternatives == nil
	responseReturn := r.Expected != "OK" || r.Alternatives != nil || len(r.Outputs) > 0
	returnType := "void"
	if !noContent {
		if responseReturn {
			returnType = "Response"
		} else {
			returnType = javaType(gen.registry, r.Type, false, "", "")
		}
	}
	var params []string
	for _, v := range r.Inputs {
		if v.Context != "" { //ignore these ones
			fmt.Fprintln(os.Stderr, "Warning: v1 style context param ignored:", v.Name, v.Context)
			continue
		}
		k := v.Name
		required := "true"
		if v.Optional {
			required = "false"
		}
		escapedComment := strings.Replace(v.Comment, `"`, `\"`, -1)
		pdecl := ""
		pdecl += "@Parameter(description = \"" + escapedComment + "\", required = " + required + ") "
		if v.QueryParam != "" {
			pdecl += fmt.Sprintf("@QueryParam(%q) ", v.QueryParam) + defaultValueAnnotation(v.Default)
		} else if v.PathParam {
			pdecl += fmt.Sprintf("@PathParam(%q) ", k)
		} else if v.Header != "" {
			pdecl += fmt.Sprintf("@HeaderParam(%q) ", v.Header)
		}
		ptype := javaType(reg, v.Type, true, "", "")
		params = append(params, pdecl+ptype+" "+javaName(k))
	}
	// include @Produces json annotation for all methods except OPTIONS
	// even if we have no content we need to have the produce annotation
	// because our errors are coming back as json objects
	var spec string
	switch r.Method {
	case "OPTIONS":
	case "POST", "PUT", "PATCH":
		if len(r.Consumes) > 0 {
			for _, v := range r.Consumes {
				spec += "@Consumes(\"" + v + "\")\n    "
			}
		} else {
			spec += "@Consumes(MediaType.APPLICATION_JSON)\n    "
		}
		fallthrough
	default:
		spec += "@Produces(MediaType.APPLICATION_JSON)\n    "
	}
	escapedComment := strings.Replace(r.Comment, `"`, `\"`, -1)
	spec += "@Operation(description = \"" + escapedComment + "\")\n    "
	methName, _ := javaMethodName(reg, r)
	return spec + "public " + returnType + " " + methName + "(\n        " + strings.Join(params, ",\n        ") + ")"
}

func defaultValueAnnotation(val interface{}) string {
	if val != nil {
		switch v := val.(type) {
		case string:
			return fmt.Sprintf("@DefaultValue(%q) ", v)
		case int8:
			return fmt.Sprintf("@DefaultValue(\"%d\") ", v)
		case int16:
			return fmt.Sprintf("@DefaultValue(\"%d\") ", v)
		case int32:
			return fmt.Sprintf("@DefaultValue(\"%d\") ", v)
		case int64:
			return fmt.Sprintf("@DefaultValue(\"%d\") ", v)
		case float32:
			return fmt.Sprintf("@DefaultValue(\"%g\") ", v)
		case float64:
			return fmt.Sprintf("@DefaultValue(\"%g\") ", v)
		default:
			return fmt.Sprintf("@DefaultValue(\"%v\") ", v)
		}
	}
	return ""
}

func (gen *javaServerGenerator) handlerReturnType(r *rdl.Resource, returnType string) string {
	if len(r.Outputs) > 0 {
		return "void"
	}
	return returnType
}

func (gen *javaServerGenerator) serverMethodSignature(r *rdl.Resource) string {
	reg := gen.registry
	noContent := r.Expected == "NO_CONTENT" && r.Alternatives == nil
	responseReturn := r.Expected != "OK" || r.Alternatives != nil || len(r.Outputs) > 0
	returnType := "void"
	if !noContent {
		if responseReturn {
			returnType = "Response"
		} else {
			returnType = javaType(gen.registry, r.Type, false, "", "")
		}
	}
	methName, params := javaMethodName(reg, r)
	sparams := ""
	if len(params) > 0 {
		sparams = ", " + strings.Join(params, ", ")
	}
	return returnType + " " + methName + "(ResourceContext context" + sparams + ")"
}

func javaMethodName(reg rdl.TypeRegistry, r *rdl.Resource) (string, []string) {
	var params []string
	bodyType := string(safeTypeVarName(r.Type))
	for _, v := range r.Inputs {
		if v.Context != "" { //ignore these legacy things
			log.Println("Warning: v1 style context param ignored:", v.Name, v.Context)
			continue
		}
		k := v.Name
		if v.QueryParam == "" && !v.PathParam && v.Header == "" {
			bodyType = string(safeTypeVarName(v.Type))
		}
		//rest_core always uses the boxed type
		params = append(params, javaType(reg, v.Type, true, "", "")+" "+javaName(k))
	}
	meth := string(r.Name)
	if meth == "" {
		meth = strings.ToLower(r.Method) + bodyType
	} else {
		meth = uncapitalize(meth)
	}
	return meth, params
}

func javaName(name rdl.Identifier) string {
	switch name {
	case "type", "default": //other reserved words
		return "_" + string(name)
	default:
		return string(name)
	}
}

func sortedExceptionKeys(excs map[string]*rdl.ExceptionDef) []string {
	var keys []string
	for ecode := range excs {
		keys = append(keys, ecode)
	}
	sort.Strings(keys)
	return keys
}
