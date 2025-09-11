package main

import (
	"fmt"
	"regexp"
)

func main() {
	id := "/subscriptions/xxxxxxxx-xxxxx-xxx-xxx-xxxx/resourceGroups/resource-group-name/providers/Microsoft.Compute/virtualMachineScaleSets/virtual-machine-scale-set-name"

	var (
		reVMSSName = regexp.MustCompile(`^/subscriptions/[^/]+/resourceGroups/[^/]+/providers/Microsoft.Compute/virtualMachineScaleSets/([^/]+)$`)
	)
	matches := reVMSSName.FindStringSubmatch(id)
	if matches == nil {
		fmt.Println("no matches")
	}
	fmt.Println(matches[1])
}
