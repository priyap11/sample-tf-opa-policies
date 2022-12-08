package stacks.c7c41a861ee541099a76cc7a70df4354.policy.gcp.iam

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
