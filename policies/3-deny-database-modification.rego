package nuon

deny contains msg if {
	resource := input.plan.resource_changes[_]
	resource.type == "aws_dynamodb_table"
	action := resource.change.actions[_]
	action == "update"
	msg := sprintf("Database modification denied: changes to '%s' could cause downtime", [resource.address])
}

deny contains msg if {
	resource := input.plan.resource_changes[_]
	resource.type == "aws_dynamodb_table"
	action := resource.change.actions[_]
	action == "delete"
	msg := sprintf("Database deletion denied: removing '%s' would cause data loss", [resource.address])
}
