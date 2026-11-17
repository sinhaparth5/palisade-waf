{{- define "palisade.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" }}
{{- end }}

{{- define "palisade.fullname" -}}
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

{{- define "palisade.selectorLabels" -}}
app.kubernetes.io/name: {{ include "palisade.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end }}

{{- define "palisade.labels" -}}
helm.sh/chart: {{ printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" }}
{{ include "palisade.selectorLabels" . }}
app.kubernetes.io/version: {{ .Values.image.tag | default .Chart.AppVersion | quote }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
{{- end }}

{{/* Name of the Secret holding the DB key, or empty when there is none. */}}
{{- define "palisade.dbKeySecret" -}}
{{- if .Values.dbKey.existingSecret }}
{{- .Values.dbKey.existingSecret }}
{{- else if .Values.dbKey.create }}
{{- printf "%s-db-key" (include "palisade.fullname" .) }}
{{- end }}
{{- end }}

{{/* "true" when Palisade serves HTTPS itself. */}}
{{- define "palisade.tls" -}}
{{- with .Values.tls }}
{{- if or .enabled .existingSecret .acme.domain .http3 }}true{{ end }}
{{- end }}
{{- end }}

{{/* A probe from values; with TLS on, plain HTTP only redirects, so probe HTTPS. */}}
{{- define "palisade.probe" -}}
{{- $p := deepCopy .probe }}
{{- if and (include "palisade.tls" .root) $p.httpGet }}
{{- $_ := set $p.httpGet "port" "https" }}
{{- $_ := set $p.httpGet "scheme" "HTTPS" }}
{{- end }}
{{- toYaml $p }}
{{- end }}

{{/* An Ingress sending path on every host to the Service name/port. */}}
{{- define "palisade.ingress" -}}
{{- $v := .values }}
apiVersion: networking.k8s.io/v1
kind: Ingress
metadata:
  name: {{ .name }}
  labels:
    {{- include "palisade.labels" .root | nindent 4 }}
  {{- with $v.annotations }}
  annotations:
    {{- toYaml . | nindent 4 }}
  {{- end }}
spec:
  {{- with $v.className }}
  ingressClassName: {{ . }}
  {{- end }}
  {{- with $v.tls }}
  tls:
    {{- toYaml . | nindent 4 }}
  {{- end }}
  rules:
    {{- range $v.hosts | default (list "") }}
    - http:
        paths:
          - path: {{ $.path }}
            pathType: Prefix
            backend:
              service:
                name: {{ $.name }}
                port:
                  name: {{ $.port }}
      {{- with . }}
      host: {{ . | quote }}
      {{- end }}
    {{- end }}
{{- end }}
