package nodeagent

import "strings"

// SmallBelow is the class rule's RAM floor: below 3.5 GiB a node is
// small (3 758 096 384 bytes, so a nominal 4 GB machine is home).
const SmallBelow = 3758096384

// Suggest is the node class suggestion (contract §20.1, vectors
// nodeclass_vectors.json): small below 3.5 GiB of RAM or on a Raspberry
// Pi, else cloud when a public address answers, else home. cpu doesn't
// change the answer.
func Suggest(mem int64, cpu int, model string, publicAnswers bool) string {
	_ = cpu
	switch {
	case mem < SmallBelow || strings.Contains(model, "Raspberry Pi"):
		return "small"
	case publicAnswers:
		return "cloud"
	default:
		return "home"
	}
}
