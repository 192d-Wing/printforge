{{/*
SPDX-License-Identifier: Apache-2.0
Copyright 2026 PrintForge Contributors
*/}}

{{/*
Expand the name of the chart.
*/}}
{{- define "printforge.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Create a default fully qualified app name.
We truncate at 63 chars because some Kubernetes name fields are limited to this
(by the DNS naming spec).
*/}}
{{- define "printforge.fullname" -}}
{{- if .Values.fullnameOverride }}
{{- .Values.fullnameOverride | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- $name := default .Chart.Name .Values.nameOverride }}
{{- if contains $name .Release.Name }}
{{- .Release.Name | trunc 63 | trimSuffix "-" }}
{{- else }}
{{- printf "%s-%s" .Release.Name $name | trunc 63 | trimSuffix "-" }}
{{- end }}
{{- end }}
{{- end }}

{{/*
Create chart name and version as used by the chart label.
*/}}
{{- define "printforge.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" }}
{{- end }}

{{/*
Common labels.
*/}}
{{- define "printforge.labels" -}}
helm.sh/chart: {{ include "printforge.chart" . }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: printforge
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}

{{/*
Selector labels for a specific component.
Usage: {{ include "printforge.selectorLabels" (dict "root" . "component" "api-gateway") }}
*/}}
{{- define "printforge.selectorLabels" -}}
app.kubernetes.io/name: {{ include "printforge.name" .root }}
app.kubernetes.io/instance: {{ .root.Release.Name }}
app.kubernetes.io/component: {{ .component }}
{{- end }}

{{/*
Component labels (common + selector).
Usage: {{ include "printforge.componentLabels" (dict "root" . "component" "api-gateway") }}
*/}}
{{- define "printforge.componentLabels" -}}
{{ include "printforge.labels" .root }}
{{ include "printforge.selectorLabels" (dict "root" .root "component" .component) }}
{{- end }}

{{/*
Service account name.
*/}}
{{- define "printforge.serviceAccountName" -}}
{{- if .Values.serviceAccount.create }}
{{- default (include "printforge.fullname" .) .Values.serviceAccount.name }}
{{- else }}
{{- default "default" .Values.serviceAccount.name }}
{{- end }}
{{- end }}

{{/*
Image reference for a component.
Usage: {{ include "printforge.image" (dict "root" . "image" .Values.apiGateway.image) }}
*/}}
{{- define "printforge.image" -}}
{{- $tag := default .root.Values.global.image.tag .image.tag -}}
{{- printf "%s/%s:%s" .root.Values.global.image.registry .image.repository $tag -}}
{{- end }}

{{/*
Standard security context for containers.
NIST 800-53 Rev 5: AC-6 (Least Privilege), CM-7 (Least Functionality)
*/}}
{{- define "printforge.securityContext" -}}
securityContext:
  runAsNonRoot: true
  runAsUser: 65534
  runAsGroup: 65534
  readOnlyRootFilesystem: true
  allowPrivilegeEscalation: false
  capabilities:
    drop:
      - ALL
  seccompProfile:
    type: RuntimeDefault
{{- end }}

{{/*
Standard pod security context.
*/}}
{{- define "printforge.podSecurityContext" -}}
securityContext:
  runAsNonRoot: true
  fsGroup: 65534
  seccompProfile:
    type: RuntimeDefault
{{- end }}
