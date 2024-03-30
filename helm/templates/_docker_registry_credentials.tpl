{{- define "util.dockerRegistryCredentials.generateDotDockerConfigJson" -}}
{{- $parent := (index . "PARENT_CONTEXT") -}}
{{- with $parent.Values.dockerRegistryCredentials -}}
{{
  printf
    "{\"auths\":{\"%s\":{\"username\":\"%s\",\"password\":\"%s\",\"auth\":\"%s\"}}}"
    .registry
    .username
    .password
    ( printf "%s:%s" .username .password | b64enc )
}}
{{- end -}}
{{- end -}}

{{- define "util.dockerRegistryCredentials._getSecretNameFromValues" -}}
{{- if .Values.dockerRegistryCredentials.name -}}
{{-
    .Values.dockerRegistryCredentials.staticName | ternary
      (.Values.dockerRegistryCredentials.name)
      (
        include "hull.metadata.fullname" (
          dict
            "PARENT_CONTEXT" .
            "COMPONENT" .Values.dockerRegistryCredentials.name
        )
      )
-}}
{{- end -}}
{{- end -}}

{{- define "util.dockerRegistryCredentials.getImagePullSecrets" -}}
{{- $parent := (index . "PARENT_CONTEXT") -}}
{{- $secret := include "util.dockerRegistryCredentials._getSecretNameFromValues" $parent -}}
{{- if $secret -}}
secrets:
- name: {{ include "util.dockerRegistryCredentials._getSecretNameFromValues" $parent -}}
{{- else -}}
secrets: []
{{- end -}}
{{- end -}}
