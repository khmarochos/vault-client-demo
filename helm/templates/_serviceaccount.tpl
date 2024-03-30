{{- define "util.serviceAccount.getName" -}}
{{- $parent := (index . "PARENT_CONTEXT") -}}
{{- $service_account := $parent.Values.serviceAccount -}}
{{- 
    ternary
      $service_account.name
      (include "hull.metadata.fullname" (
        dict
          "PARENT_CONTEXT" $parent
          "COMPONENT" $service_account.name
      ))
    $service_account.staticName
-}}
{{- end -}}
