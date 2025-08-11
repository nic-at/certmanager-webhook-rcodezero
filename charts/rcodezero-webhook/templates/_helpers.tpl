{{/* vim: set filetype=mustache: */}}
{{/*
Expand the name of the chart.
*/}}
{{- define "certmanager-webhook-rcodezero.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this (by the DNS naming spec).
If release name contains chart name it will be used as a full name.
*/}}
{{- define "certmanager-webhook-rcodezero.fullname" -}}
{{- if .Values.fullnameOverride -}}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- $name := default .Chart.Name .Values.nameOverride -}}
{{- if contains $name .Release.Name -}}
{{- .Release.Name | trunc 63 | trimSuffix "-" -}}
{{- else -}}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" -}}
{{- end -}}
{{- end -}}
{{- end -}}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "certmanager-webhook-rcodezero.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{- define "certmanager-webhook-rcodezero.selfSignedIssuer" -}}
{{ printf "%s-selfsign" (include "certmanager-webhook-rcodezero.fullname" .) }}
{{- end -}}

{{- define "certmanager-webhook-rcodezero.rootCAIssuer" -}}
{{ printf "%s-ca" (include "certmanager-webhook-rcodezero.fullname" .) }}
{{- end -}}

{{- define "certmanager-webhook-rcodezero.rootCACertificate" -}}
{{ printf "%s-ca" (include "certmanager-webhook-rcodezero.fullname" .) }}
{{- end -}}

{{- define "certmanager-webhook-rcodezero.servingCertificate" -}}
{{ printf "%s-webhook-tls" (include "certmanager-webhook-rcodezero.fullname" .) }}
{{- end -}}

{{/*
Common labels
*/}}
{{- define "certmanager-webhook-rcodezero.labels" -}}
helm.sh/chart: {{ include "certmanager-webhook-rcodezero.chart" . }}
{{ include "certmanager-webhook-rcodezero.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}


{{/*
Selector labels
*/}}
{{- define "certmanager-webhook-rcodezero.selectorLabels" -}}
app.kubernetes.io/name: {{ include "certmanager-webhook-rcodezero.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}