// Copyright The Athenz Authors
// Modified to generate java client code for Athenz Clients
// Licensed under the terms of the Apache version 2.0 license. See LICENSE file for terms.

package main

import (
	"bufio"
	"bytes"
	"fmt"
	"io"
	"log"
	"os"
	"path/filepath"
	"strings"
	"text/template"

	"github.com/ardielle/ardielle-go/rdl"
)

type GeneratorParams struct {
	Outdir    string
	Banner    string
	Namespace string
	ClassName string
}

type javaClientGenerator struct {
	registry rdl.TypeRegistry
	schema   *rdl.Schema
	name     string
	writer   *bufio.Writer
	err      error
	banner   string
	ns       string
}

// GenerateJavaClient generates the client code to talk to the server
func GenerateAthenzJavaClient(schema *rdl.Schema, params *GeneratorParams) error {
	reg := rdl.NewTypeRegistry(schema)
	packageDir, err := javaGenerationDir(params.Outdir, schema, params.Namespace)
	if err != nil {
		return err
	}

	cName := params.ClassName
	if cName == "" {
		cName = capitalize(string(schema.Name))
	}

	out, file, _, err := outputWriter(packageDir, cName, "Client.java")
	if err != nil {
		return err
	}
	gen := &javaClientGenerator{reg, schema, cName, out, nil, params.Banner, params.Namespace}
	gen.processTemplate(javaClientTemplate)
	out.Flush()
	file.Close()
	if gen.err != nil {
		return gen.err
	}

	//ResourceException - the throawable wrapper for alternate return types
	out, file, _, err = outputWriter(packageDir, "ResourceException", ".java")
	if err != nil {
		return err
	}
	err = javaGenerateResourceException(params.Banner, schema, out, params.Namespace)
	out.Flush()
	file.Close()
	if err != nil {
		return err
	}

	//ResourceError - the default data object for an error
	out, file, _, err = outputWriter(packageDir, "ResourceError", ".java")
	if err != nil {
		return err
	}
	err = javaGenerateResourceError(params.Banner, schema, out, params.Namespace)
	out.Flush()
	file.Close()
	return err
}

func (gen *javaClientGenerator) processTemplate(templateSource string) error {
	commentFun := func(s string) string {
		return formatComment(s, 0)
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
		"comment":    commentFun,
		"methodSig":  func(r *rdl.Resource) string { return gen.clientMethodSignature(r) },
		"methodBody": func(r *rdl.Resource) string { return gen.clientMethodBody(r) },
		"name":       func() string { return gen.name },
		"cName":      func() string { return capitalize(gen.name) },
		"lName":      func() string { return uncapitalize(gen.name) },
	}
	t := template.Must(template.New(gen.name).Funcs(funcMap).Parse(templateSource))
	return t.Execute(gen.writer, gen.schema)
}

func (gen *javaClientGenerator) resourcePath(r *rdl.Resource) string {
	path := r.Path
	i := strings.Index(path, "?")
	if i >= 0 {
		path = path[0:i]
	}
	return path
}

const javaClientTemplate = `{{header}}
{{package}}

import com.fasterxml.jackson.databind.DeserializationFeature;
import com.fasterxml.jackson.databind.ObjectMapper;
import org.apache.http.HttpEntity;
import org.apache.http.client.CookieStore;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpUriRequest;
import org.apache.http.client.methods.RequestBuilder;
import org.apache.http.client.protocol.HttpClientContext;
import org.apache.http.client.utils.URIBuilder;
import org.apache.http.entity.ContentType;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.BasicCookieStore;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;
import org.apache.http.impl.cookie.BasicClientCookie;
import org.apache.http.protocol.BasicHttpContext;
import org.apache.http.protocol.HttpContext;
import org.apache.http.util.EntityUtils;

import javax.net.ssl.HostnameVerifier;
import java.io.IOException;
import java.net.URISyntaxException;
import java.util.List;
import com.yahoo.rdl.Schema;

public class {{cName}}Client {

    private static final int DEFAULT_CLIENT_CONNECT_TIMEOUT_MS = 5000;
    private static final int DEFAULT_CLIENT_READ_TIMEOUT_MS = 30000;

    private String baseUrl;
    private String credsHeader;
    private String credsToken;

    private CloseableHttpClient client;
    private HttpContext httpContext;
    private ObjectMapper jsonMapper;

    protected CloseableHttpClient createHttpClient(HostnameVerifier hostnameVerifier) {
        RequestConfig config = RequestConfig.custom()
                .setConnectTimeout(DEFAULT_CLIENT_CONNECT_TIMEOUT_MS)
                .setSocketTimeout(DEFAULT_CLIENT_READ_TIMEOUT_MS)
                .setRedirectsEnabled(false)
                .build();
        return HttpClients.custom()
                .setDefaultRequestConfig(config)
                .setSSLHostnameVerifier(hostnameVerifier)
                .build();
    }

    private static class UriTemplateBuilder {
        private final String baseUrl;
        private String basePath;
        public UriTemplateBuilder(final String url, final String path) {
            baseUrl = url;
            basePath = path;
        }
        public UriTemplateBuilder resolveTemplate(final String key, final Object value) {
            basePath = basePath.replace("{" + key + "}", String.valueOf(value));
            return this;
        }
        public String getUri() {
            return baseUrl + basePath;
        }
    }

    public {{cName}}Client(final String url) {
        initClient(url, createHttpClient(null));
    }

    public {{cName}}Client(final String url, HostnameVerifier hostnameVerifier) {
        initClient(url, createHttpClient(hostnameVerifier));
    }

    public {{cName}}Client(final String url, CloseableHttpClient httpClient) {
        initClient(url, httpClient);
    }

    private void initClient(final String url, CloseableHttpClient httpClient) {
        baseUrl = url;
        client = httpClient;
        jsonMapper = new ObjectMapper();
        jsonMapper.configure(DeserializationFeature.FAIL_ON_UNKNOWN_PROPERTIES, false);
    }

    public void close() {
        try {
            client.close();
        } catch (IOException ignored) {
        }
    }

    public void addCredentials(final String header, final String token) {

        credsHeader = header;
        credsToken = token;

        if (header == null) {
            httpContext = null;
        } else if (header.startsWith("Cookie.")) {
            httpContext = new BasicHttpContext();
            CookieStore cookieStore = new BasicCookieStore();
            BasicClientCookie cookie = new BasicClientCookie(header.substring(7), token);
            cookie.setPath(baseUrl);
            cookieStore.addCookie(cookie);
            httpContext.setAttribute(HttpClientContext.COOKIE_STORE, cookieStore);
            credsHeader = null;
        }
    }

    public void setHttpClient(CloseableHttpClient httpClient) {
        client = httpClient;
    }
{{range .Resources}}
    {{methodSig .}} {
        {{methodBody .}}
    }
{{end}}
}
`

func (gen *javaClientGenerator) clientMethodSignature(r *rdl.Resource) string {
	reg := gen.registry
	returnType := javaType(reg, r.Type, false, "", "")
	methName, params := javaMethodName(reg, r)
	sparams := ""
	if len(params) > 0 {
		sparams = strings.Join(params, ", ")
	}
	if len(r.Outputs) > 0 {
		if sparams == "" {
			sparams = "java.util.Map<String, java.util.List<String>> headers"
		} else {
			sparams = sparams + ", java.util.Map<String, java.util.List<String>> headers"
		}
	}
	return "public " + returnType + " " + methName + "(" + sparams + ") throws URISyntaxException, IOException"
}

func (gen *javaClientGenerator) clientMethodBody(r *rdl.Resource) string {
	reg := gen.registry
	returnType := javaType(reg, r.Type, false, "", "")
	path := r.Path
	s := "UriTemplateBuilder uriTemplateBuilder = new UriTemplateBuilder(baseUrl, \"" + path + "\")"
	entityName := ""
	q := ""
	h := ""
	for _, in := range r.Inputs {
		iname := javaName(in.Name)
		if in.PathParam {
			s += "\n            .resolveTemplate(\"" + iname + "\", " + iname + ")"
		} else if in.QueryParam != "" {
			qParamName := iname
			if javaType(reg, in.Type, false, "", "") != "String" {
				qParamName = "String.valueOf(" + iname + ")"
			}
			q += "\n        if (" + iname + " != null) {"
			q += "\n            uriBuilder.setParameter(\"" + in.QueryParam + "\", " + qParamName + ");"
			q += "\n        }"
		} else if in.Header != "" {
			h += "\n        if (" + iname + " != null) {"
			if in.Type == "String" {
				h += "\n            httpUriRequest.addHeader(\"" + in.Header + "\", " + iname + ");"
			} else {
				h += "\n            httpUriRequest.addHeader(\"" + in.Header + "\", String.valueOf(" + iname + "));"
			}
			h += "\n        }"
		} else { //the entity
			entityName = iname
		}
	}
	s += ";"
	s += "\n        URIBuilder uriBuilder = new URIBuilder(uriTemplateBuilder.getUri());"
	if q != "" {
		s += q
	}

	obj := ""
	switch r.Method {
	case "PUT", "POST", "PATCH":
		if len(r.Consumes) > 0 {
			s += "\n        HttpEntity httpEntity = new StringEntity(" + entityName + ", ContentType.create(\"" + r.Consumes[0] + "\"));"
		} else {
			s += "\n        HttpEntity httpEntity = new StringEntity(jsonMapper.writeValueAsString(" + entityName + "), ContentType.APPLICATION_JSON);"
		}
		obj += "\n            .setEntity(httpEntity)"
	}

	s += "\n        HttpUriRequest httpUriRequest = RequestBuilder." + strings.ToLower(r.Method) + "()"
	s += "\n            .setUri(uriBuilder.build())"
	s += obj
	s += "\n            .build();"

	if r.Auth != nil {
		if r.Auth.Authenticate || (r.Auth.Action != "" && r.Auth.Resource != "") {
			s += "\n        if (credsHeader != null) {"
			s += "\n            httpUriRequest.addHeader(credsHeader, credsToken);"
			s += "\n        }"
		} else {
			log.Println("*** Badly formed auth spec in resource input:", r)
		}
	}
	if h != "" {
		s += h
	}
	s += "\n"
	s += "        HttpEntity httpResponseEntity = null;\n"
	s += "        try (CloseableHttpResponse httpResponse = client.execute(httpUriRequest, httpContext)) {\n"
	s += "            int code = httpResponse.getStatusLine().getStatusCode();\n"
	s += "            httpResponseEntity = httpResponse.getEntity();\n"
	s += "            switch (code) {\n"

	//loop for all expected results
	var expected []string
	expected = append(expected, rdl.StatusCode(r.Expected))
	couldBeNoContent := "NO_CONTENT" == r.Expected
	couldBeNotModified := "NOT_MODIFIED" == r.Expected
	couldBeRedirect := "FOUND" == r.Expected
	noContent := couldBeNoContent && r.Alternatives == nil
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
	for _, expCode := range expected {
		s += "            case " + expCode + ":\n"
	}
	if len(r.Outputs) > 0 {
		s += "                if (headers != null) {\n"
		for _, out := range r.Outputs {
			s += "                    headers.put(\"" + string(out.Name) + "\", List.of(httpResponse.getFirstHeader(\"" + out.Header + "\").getValue()));\n"
		}
		s += "                }\n"
	}
	if noContent {
		s += "                return null;\n"
	} else {
		if couldBeNoContent || couldBeNotModified || couldBeRedirect {
			s += "                if (" + gen.responseCondition(couldBeNoContent, couldBeNotModified, couldBeRedirect) + ") {\n"
			s += "                    return null;\n"
			s += "                }\n"
		}
		s += "                return jsonMapper.readValue(httpResponseEntity.getContent(), " + returnType + ".class);\n"
	}
	s += "            default:\n"
	s += "                final String errorData = (httpResponseEntity == null) ? null : EntityUtils.toString(httpResponseEntity);\n"
	if r.Exceptions != nil {
		s += "                throw (errorData != null && !errorData.isEmpty())\n"
		s += "                    ? new ResourceException(code, jsonMapper.readValue(errorData, ResourceError.class))\n"
		s += "                    : new ResourceException(code);\n"
	} else {
		s += "                throw (errorData != null && !errorData.isEmpty())\n"
		s += "                    ? new ResourceException(code, jsonMapper.readValue(errorData, Object.class))\n"
		s += "                    : new ResourceException(code);\n"
	}
	s += "            }\n"
	s += "        } finally {\n"
	s += "            EntityUtils.consumeQuietly(httpResponseEntity);\n"
	s += "        }"
	return s
}

func (gen *javaClientGenerator) responseCondition(noContent, notModified, redirect bool) string {
	var s string
	if noContent {
		s += "code == " + rdl.StatusCode("NO_CONTENT")
	}
	if notModified {
		if s != "" {
			s += " || "
		}
		s += "code == " + rdl.StatusCode("NOT_MODIFIED")
	}
	if redirect {
		if s != "" {
			s += " || "
		}
		s += "code == " + rdl.StatusCode("FOUND")
	}
	return s
}

func javaGenerationHeader(banner string) string {
	return fmt.Sprintf("//\n// This file generated by %s. Do not modify!\n//", banner)
}

func javaGenerationPackage(schema *rdl.Schema, ns string) string {
	if ns != "" {
		return ns
	}
	return string(schema.Namespace)
}

func javaGenerationDir(outdir string, schema *rdl.Schema, ns string) (string, error) {
	dir := outdir
	if dir == "" {
		dir = "./src/main/java"
	}
	pack := javaGenerationPackage(schema, ns)
	if pack != "" {
		dir += "/" + strings.Replace(pack, ".", "/", -1)
	}
	_, err := os.Stat(dir)
	if err != nil {
		err = os.MkdirAll(dir, 0755)
	}
	return dir, err
}

func javaGenerateResourceError(banner string, schema *rdl.Schema, writer io.Writer, ns string) error {
	funcMap := template.FuncMap{
		"header": func() string { return javaGenerationHeader(banner) },
		"package": func() string {
			s := javaGenerationPackage(schema, ns)
			if s == "" {
				return s
			}
			return "package " + s + ";\n"
		},
	}
	t := template.Must(template.New("util").Funcs(funcMap).Parse(javaResourceErrorTemplate))
	return t.Execute(writer, schema)
}

const javaResourceErrorTemplate = `{{header}}
{{package}}
public class ResourceError {

    public int code;
    public String message;

    public ResourceError code(int code) {
        this.code = code;
        return this;
    }
    public ResourceError message(String message) {
        this.message = message;
        return this;
    }

    public String toString() {
        return "{code: " + code + ", message: \"" + message + "\"}";
    }

}
`

func javaGenerateResourceException(banner string, schema *rdl.Schema, writer io.Writer, ns string) error {
	funcMap := template.FuncMap{
		"header": func() string { return javaGenerationHeader(banner) },
		"package": func() string {
			s := javaGenerationPackage(schema, ns)
			if s == "" {
				return s
			}
			return "package " + s + ";\n"
		},
	}
	t := template.Must(template.New("util").Funcs(funcMap).Parse(javaResourceExceptionTemplate))
	return t.Execute(writer, schema)
}

const javaResourceExceptionTemplate = `{{header}}
{{package}}
public class ResourceException extends RuntimeException {
    public static final int OK = 200;
    public static final int CREATED = 201;
    public static final int ACCEPTED = 202;
    public static final int NO_CONTENT = 204;
    public static final int MOVED_PERMANENTLY = 301;
    public static final int FOUND = 302;
    public static final int SEE_OTHER = 303;
    public static final int NOT_MODIFIED = 304;
    public static final int TEMPORARY_REDIRECT = 307;
    public static final int BAD_REQUEST = 400;
    public static final int UNAUTHORIZED = 401;
    public static final int FORBIDDEN = 403;
    public static final int NOT_FOUND = 404;
    public static final int CONFLICT = 409;
    public static final int GONE = 410;
    public static final int PRECONDITION_FAILED = 412;
    public static final int UNSUPPORTED_MEDIA_TYPE = 415;
    public static final int PRECONDITION_REQUIRED = 428;
    public static final int TOO_MANY_REQUESTS = 429;
    public static final int REQUEST_HEADER_FIELDS_TOO_LARGE = 431;
    public static final int INTERNAL_SERVER_ERROR = 500;
    public static final int NOT_IMPLEMENTED = 501;
    public static final int SERVICE_UNAVAILABLE = 503;
    public static final int NETWORK_AUTHENTICATION_REQUIRED = 511;

    public static String codeToString(int code) {
        switch (code) {
        case OK: return "OK";
        case CREATED: return "Created";
        case ACCEPTED: return "Accepted";
        case NO_CONTENT: return "No Content";
        case MOVED_PERMANENTLY: return "Moved Permanently";
        case FOUND: return "Found";
        case SEE_OTHER: return "See Other";
        case NOT_MODIFIED: return "Not Modified";
        case TEMPORARY_REDIRECT: return "Temporary Redirect";
        case BAD_REQUEST: return "Bad Request";
        case UNAUTHORIZED: return "Unauthorized";
        case FORBIDDEN: return "Forbidden";
        case NOT_FOUND: return "Not Found";
        case CONFLICT: return "Conflict";
        case GONE: return "Gone";
        case PRECONDITION_FAILED: return "Precondition Failed";
        case UNSUPPORTED_MEDIA_TYPE: return "Unsupported Media Type";
        case PRECONDITION_REQUIRED: return "Precondition Required";
        case TOO_MANY_REQUESTS: return "Too Many Requests";
        case REQUEST_HEADER_FIELDS_TOO_LARGE: return "Request Header Fields Too Large";
        case INTERNAL_SERVER_ERROR: return "Internal Server Error";
        case NOT_IMPLEMENTED: return "Not Implemented";
        case SERVICE_UNAVAILABLE: return "Service Unavailable";
        case NETWORK_AUTHENTICATION_REQUIRED: return "Network Authentication Required";
        default: return "" + code;
        }
    }

    int code;
    Object data;

    public ResourceException(int code) {
        this(code, new ResourceError().code(code).message(codeToString(code)));
    }

    public ResourceException(int code, Object data) {
        super("ResourceException (" + code + "): " + data);
        this.code = code;
        this.data = data;
    }

    public int getCode() {
        return code;
    }

    public Object getData() {
        return data;
    }

    public <T> T getData(Class<T> cl) {
        return cl.cast(data);
    }

}
`

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

func safeTypeVarName(rtype rdl.TypeRef) rdl.TypeName {
	tokens := strings.Split(string(rtype), ".")
	return rdl.TypeName(capitalize(strings.Join(tokens, "")))
}

func javaType(reg rdl.TypeRegistry, rdlType rdl.TypeRef, optional bool, items rdl.TypeRef, keys rdl.TypeRef) string {
	t := reg.FindType(rdlType)
	if t == nil || t.Variant == 0 {
		panic("Cannot find type '" + rdlType + "'")
	}
	bt := reg.BaseType(t)
	switch bt {
	case rdl.BaseTypeAny:
		return "Object"
	case rdl.BaseTypeString:
		return "String"
	case rdl.BaseTypeSymbol, rdl.BaseTypeTimestamp, rdl.BaseTypeUUID:
		return string(rdlType)
	case rdl.BaseTypeBool:
		if optional {
			return "Boolean"
		}
		return "boolean"
	case rdl.BaseTypeInt8:
		if optional {
			return "Byte"
		}
		return "byte"
	case rdl.BaseTypeInt16:
		if optional {
			return "Short"
		}
		return "short"
	case rdl.BaseTypeInt32:
		if optional {
			return "Integer"
		}
		return "int"
	case rdl.BaseTypeInt64:
		if optional {
			return "Long"
		}
		return "long"
	case rdl.BaseTypeFloat32:
		if optional {
			return "Float"
		}
		return "float"
	case rdl.BaseTypeFloat64:
		if optional {
			return "Double"
		}
		return "double"
	case rdl.BaseTypeArray:
		i := rdl.TypeRef("Any")
		switch t.Variant {
		case rdl.TypeVariantArrayTypeDef:
			i = t.ArrayTypeDef.Items
		default:
			if items != "" && items != "Any" {
				i = items
			}
		}
		gitems := javaType(reg, i, true, "", "")
		return "List<" + gitems + ">"
	case rdl.BaseTypeMap:
		k := rdl.TypeRef("Any")
		i := rdl.TypeRef("Any")
		switch t.Variant {
		case rdl.TypeVariantMapTypeDef:
			k = t.MapTypeDef.Keys
			i = t.MapTypeDef.Items
		default:
			if keys != "" && keys != "Any" {
				k = keys
			}
			if items != "" && items != "Any" {
				i = items
			}
		}
		gkeys := javaType(reg, k, true, "", "")
		gitems := javaType(reg, i, true, "", "")
		return "Map<" + gkeys + ", " + gitems + ">"
	case rdl.BaseTypeStruct:
		if strings.HasPrefix(string(rdlType), "rdl.") {
			return string(rdlType)[4:]
		}
		switch t.Variant {
		case rdl.TypeVariantStructTypeDef:
			if t.StructTypeDef.Name == "Struct" {
				return "Object"
			}
		}
		return string(rdlType)
	default:
		return string(rdlType)
	}
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
