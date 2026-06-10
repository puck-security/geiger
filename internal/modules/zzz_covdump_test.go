package modules

import (
	"fmt"
	"sort"
	"testing"

	"github.com/puck-security/geiger/internal/module"
)

func TestZZZCoverageDump(t *testing.T) {
	dummy := []module.Finding{{Key: "reach", Value: "x", Flag: module.FlagInfo}}
	var lines []string
	for _, m := range module.Default.All() {
		s := m.Summarize("x", dummy).Summary
		lines = append(lines, fmt.Sprintf("%-26s | %s", m.Name(), s))
	}
	sort.Strings(lines)
	for _, l := range lines {
		fmt.Println(l)
	}
	fmt.Println("TOTAL", len(lines))
}
