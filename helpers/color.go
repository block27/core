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

	// MagentaFgB ...
	MagentaFgB = color.New(color.FgMagenta, color.Bold).SprintFunc()

	// MagentaFgD ...
	MagentaFgD = color.New(color.FgMagenta).SprintFunc()

	// RedFgD
	RedFgD = color.New(color.FgRed).SprintFunc()

	// RedFgB
	RedFgB = color.New(color.FgRed, color.Bold).SprintFunc()
)
