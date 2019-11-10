package helpers

import (
	"github.com/fatih/color"
)

var (
	// Colors - to be used in spinner, randomize them
	Colors = []string{"fgRed", "fgGreen", "fgYellow", "fgBlue", "fgMagenta", "fgCyan"}

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

	// RedFgD ...
	RedFgD = color.New(color.FgRed).SprintFunc()

	// RedFgB ...
	RedFgB = color.New(color.FgRed, color.Bold).SprintFunc()

	// WhiteFgD ...
	WhiteFgD = color.New(color.FgWhite).SprintFunc()

	// WhiteFgB ...
	WhiteFgB = color.New(color.FgWhite, color.Bold).SprintFunc()

	// YellowFgD ...
	YellowFgD = color.New(color.FgYellow).SprintFunc()

	// YellowFgB ...
	YellowFgB = color.New(color.FgYellow, color.Bold).SprintFunc()
)
