package helpers

import (
	"github.com/fatih/color"
)

var (
	// CyanFgB ...
	CyanFgB = color.New(color.FgHiCyan, color.Bold).SprintFunc()

	// CyanFgD ...
	CyanFgD = color.New(color.FgHiCyan).SprintFunc()

	// GreenFgB ...
	GreenFgB = color.New(color.FgHiGreen, color.Bold).SprintFunc()

	// GreenFgD ...
	GreenFgD = color.New(color.FgHiGreen).SprintFunc()

	// MagentaFgD ...
	MagentaFgD = color.New(color.FgMagenta).SprintFunc()
)
