
{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "athenz-zts.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "athenz-zts.fullname" -}}
{{- printf "%s-%s" .Release.Name "athenz-zts" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "athenz-zts.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Return the proper ZTS image name
*/}}
{{- define "athenz-zts.image" -}}
{{- $registryName := .Values.image.registry -}}
{{- $repositoryName := .Values.image.repository -}}
{{- $tag := .Values.image.tag | toString -}}
{{- if .Values.global }}
    {{- if .Values.global.imageRegistry }}
        {{- printf "%s/%s:%s" .Values.global.imageRegistry $repositoryName $tag -}}
    {{- else -}}
        {{- printf "%s/%s:%s" $registryName $repositoryName $tag -}}
    {{- end -}}
{{- else -}}
    {{- printf "%s/%s:%s" $registryName $repositoryName $tag -}}
{{- end -}}
{{- end -}}

{{/*
Return the proper ZTS setup image name
*/}}
{{- define "athenz-zts.setup.image" -}}
{{- $registryName := .Values.image.registry -}}
{{- $repositoryName := .Values.image.setup.repository -}}
{{- $tag := .Values.image.setup.tag | toString -}}
{{- if .Values.global }}
    {{- if .Values.global.imageRegistry }}
        {{- printf "%s/%s:%s" .Values.global.imageRegistry $repositoryName $tag -}}
    {{- else -}}
        {{- printf "%s/%s:%s" $registryName $repositoryName $tag -}}
    {{- end -}}
{{- else -}}
    {{- printf "%s/%s:%s" $registryName $repositoryName $tag -}}
{{- end -}}
{{- end -}}

{{/*
Return the proper Docker Image Registry Secret Names
*/}}
{{- define "athenz-zts.imagePullSecrets" -}}
{{- if .Values.global }}
{{- if .Values.global.imagePullSecrets }}
imagePullSecrets:
{{- range .Values.global.imagePullSecrets }}
  - name: {{ . }}
{{- end }}
{{- else if .Values.image.pullSecrets }}
imagePullSecrets:
{{- range .Values.image.pullSecrets }}
  - name: {{ . }}
{{- end }}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Return the name of the Secret storing the private key and passwords
*/}}
{{- define "athenz-zts.secretName" -}}
{{- if .Values.existingSecret -}}
{{ .Values.existingSecret }}
{{- else -}}
{{ template "athenz-zts.fullname" . }}
{{- end -}}
{{- end -}}

{{/*
Return the name of the TLS Secret
*/}}
{{- define "athenz-zts.tls.secretName" -}}
{{- if .Values.existingTLSSecret -}}
{{ .Values.existingTLSSecret }}
{{- else -}}
{{ template "athenz-zts.fullname" . }}-tls
{{- end -}}
{{- end -}}

{{/*
Return the name of the Secret storing the trusted CA certificates
*/}}
{{- define "athenz-zts.tls.ca.secretName" -}}
{{- if .Values.existingTLSCASecret -}}
{{ .Values.existingTLSCASecret }}
{{- else -}}
{{ template "athenz-zts.fullname" . }}-tls-ca
{{- end -}}
{{- end -}}

{{/*
Return the name of the ZMS client mTLS Secret
*/}}
{{- define "athenz-zts.zmsClient.secretName" -}}
{{- if .Values.existingZMSClientSecret -}}
{{ .Values.existingZMSClientSecret }}
{{- else -}}
{{ template "athenz-zts.fullname" . }}-zms
{{- end -}}
{{- end -}}

{{/*
Return the name of the Secret storing the ZMS client trusted CA certificates
*/}}
{{- define "athenz-zts.zmsClient.ca.secretName" -}}
{{- if .Values.existingZMSClientCASecret -}}
{{ .Values.existingZMSClientCASecret }}
{{- else -}}
{{ template "athenz-zts.fullname" . }}-zms-ca
{{- end -}}
{{- end -}}

{{/*
Return the name of the ZTS singer Secret
*/}}
{{- define "athenz-zts.signer.secretName" -}}
{{- if .Values.existingSignerSecret -}}
{{ .Values.existingSignerSecret }}
{{- else -}}
{{ template "athenz-zts.fullname" . }}-signer
{{- end -}}
{{- end -}}

{{/*
Return the name of the Secret storing the ZTS HTTP client trusted CA certificates
*/}}
{{- define "athenz-zts.signer.ca.secretName" -}}
{{- if .Values.existingSignerCASecret -}}
{{ .Values.existingSignerCASecret }}
{{- else -}}
{{ template "athenz-zts.fullname" . }}-signer-ca
{{- end -}}
{{- end -}}

{{/*
Return the metrics port, empty string if disable
*/}}
{{- define "athenz-zts.metrics.port" -}}
{{- $file := .Files -}}
{{- $enable := false -}}
{{- $httpEnable := false -}}
{{- $port := "" -}}
{{- range $path, $byte := .Files.Glob .Values.files.conf -}}
    {{- range $line := $file.Lines $path }}
        {{- if eq $line "athenz.metrics.prometheus.enable=true" }}
            {{- $enable = true }}
        {{- end }}
        {{- if eq $line "athenz.metrics.prometheus.http_server.enable=true" }}
            {{- $httpEnable = true }}
        {{- end }}
        {{- $found := regexFind "^athenz\\.metrics\\.prometheus\\.http_server\\.port=(\\d+)$" $line }}
        {{- if $found }}
            {{- $port = ($found | trimPrefix "athenz.metrics.prometheus.http_server.port=") }}
        {{- end }}
    {{- end }}
{{- end -}}
{{- if and $enable $httpEnable -}}
{{- $port -}}
{{- end -}}
{{- end -}}

{{/*
Return the athenz.conf path
*/}}
{{- define "athenz-zts.athenz_conf" -}}
{{- $file := .Files -}}
{{- range $path, $byte := .Files.Glob .Values.files.conf -}}
    {{- range $line := $file.Lines $path }}
        {{- $found := regexFind "^athenz\\.athenz_conf=(.+)" $line }}
        {{- if $found }}
            {{- $found | trimPrefix "athenz.athenz_conf=" }}
        {{- end }}
    {{- end }}
{{- end -}}
{{- end -}}
