package helpers

import (
	"github.com/fatih/color"
)

var (
	// Cyan - cyan with Fg and bolding
	Cyan = color.New(color.FgHiCyan, color.Bold).SprintFunc()

	// Green - green with Fg and bolding
	Green = color.New(color.FgHiGreen, color.Bold).SprintFunc()
)
