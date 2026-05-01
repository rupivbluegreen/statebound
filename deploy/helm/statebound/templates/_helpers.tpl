{{/*
Expand the name of the chart.
*/}}
{{- define "statebound.name" -}}
{{- default .Chart.Name .Values.nameOverride | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Fully qualified app name. Falls back to release-chart when fullnameOverride
is not set, with a 63-character truncation to satisfy DNS label rules.
*/}}
{{- define "statebound.fullname" -}}
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
{{- define "statebound.chart" -}}
{{- printf "%s-%s" .Chart.Name .Chart.Version | replace "+" "_" | trunc 63 | trimSuffix "-" -}}
{{- end -}}

{{/*
Common labels.
*/}}
{{- define "statebound.labels" -}}
helm.sh/chart: {{ include "statebound.chart" . }}
{{ include "statebound.selectorLabels" . }}
{{- if .Chart.AppVersion }}
app.kubernetes.io/version: {{ .Chart.AppVersion | quote }}
{{- end }}
app.kubernetes.io/managed-by: {{ .Release.Service }}
app.kubernetes.io/part-of: statebound
{{- end -}}

{{/*
Selector labels.
*/}}
{{- define "statebound.selectorLabels" -}}
app.kubernetes.io/name: {{ include "statebound.name" . }}
app.kubernetes.io/instance: {{ .Release.Name }}
{{- end -}}

{{/*
ServiceAccount name. Returns the user-supplied name when present,
otherwise derives one from the fullname.
*/}}
{{- define "statebound.serviceAccountName" -}}
{{- if .Values.serviceAccount.create -}}
{{- default (include "statebound.fullname" .) .Values.serviceAccount.name -}}
{{- else -}}
{{- default "default" .Values.serviceAccount.name -}}
{{- end -}}
{{- end -}}

{{/*
Image reference. Resolves .Values.image.tag, falling back to
.Chart.AppVersion when the value is empty.
*/}}
{{- define "statebound.image" -}}
{{- $tag := .Values.image.tag | default .Chart.AppVersion -}}
{{- printf "%s:%s" .Values.image.repository $tag -}}
{{- end -}}

{{/*
Sanity check: at least one auth mode must be configured. The chart
fails to render if neither OIDC nor a dev token is set, because the
binary refuses to start in that state.
*/}}
{{- define "statebound.assertAuthConfigured" -}}
{{- if and (not .Values.api.devToken) (not .Values.api.oidc.issuer) -}}
{{- fail "statebound chart: either .Values.api.oidc.issuer (production) or .Values.api.devToken (dev) must be set" -}}
{{- end -}}
{{- end -}}

{{/*
Sanity check: when devSkip plan signing is enabled but OIDC is
configured, refuse to render. A cluster with real OIDC should not
quietly skip plan signatures.
*/}}
{{- define "statebound.assertSigningSane" -}}
{{- if and .Values.signing.devSkip .Values.api.oidc.issuer -}}
{{- fail "statebound chart: signing.devSkip=true is incompatible with api.oidc.issuer (refusing to ship unsigned plans into a real-OIDC cluster)" -}}
{{- end -}}
{{- end -}}
