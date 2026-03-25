package nuon

deny contains msg if {
	input.review.kind.kind == "Deployment"
	container := input.review.object.spec.template.spec.containers[_]
	not contains(container.image, ".dkr.ecr.")
	msg := sprintf("Container '%s' uses non-ECR image '%s'; all images must be stored in the install's ECR repository", [container.name, container.image])
}

deny contains msg if {
	input.review.kind.kind == "Pod"
	container := input.review.object.spec.containers[_]
	not contains(container.image, ".dkr.ecr.")
	msg := sprintf("Container '%s' uses non-ECR image '%s'; all images must be stored in the install's ECR repository", [container.name, container.image])
}
