package stacks.bc38ae749e214feb88059689eb1a44a5.policy.gcp.iam

import input
enforce[decision] {
  #title: Restrict setIamPolicy permissions from custom roles
  resource := input.resource_changes[_]
  resource.mode == "managed"
  resource.type == "google_project_iam_custom_role"
  bad_permissions := resource.change.after.permissions
  contains(bad_permissions[_], "setIamPolicy") == true
  decision := sprintf("%-40s :: setIamPolicy permissions should not be used in custom role", [resource.address])
}
