package helpers

import (
	"github.com/fatih/color"
)

var (
	// Cyan - cyan with Fg and bolding
	CyanFgB = color.New(color.FgHiCyan, color.Bold).SprintFunc()

	// Green - green with Fg and bolding
	GreenFgB = color.New(color.FgHiGreen, color.Bold).SprintFunc()

	// Green - green with standard Fg formatting
	GreenStD = color.New(color.FgHiGreen).SprintFunc()
)
