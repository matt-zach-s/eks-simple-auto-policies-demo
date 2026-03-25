package nuon

restricted_namespaces := {"default", "kube-system", "kube-public"}

deny contains msg if {
	ns := input.review.object.metadata.namespace
	restricted_namespaces[ns]
	msg := sprintf("Deployment to namespace '%s' is restricted (%s)", [ns, input.review.object.metadata.name])
}
