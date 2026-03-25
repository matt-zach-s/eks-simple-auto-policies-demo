package nuon

runner_role_patterns := ["provision", "maintenance", "deprovision"]

is_runner_role(principal_arn) if {
	pattern := runner_role_patterns[_]
	contains(principal_arn, pattern)
}

deny contains msg if {
	resource := input.plan.resource_changes[_]
	resource.type == "aws_eks_access_entry"
	resource.change.actions[_] == "create"
	principal := resource.change.after.principal_arn
	not is_runner_role(principal)
	msg := sprintf("EKS access entry for non-runner principal '%s' is not allowed", [principal])
}
