package helpers

import (
	"github.com/fatih/color"
)

var (
	// Colors - to be used in spinner, randomize them
	Colors = []string{"fgRed", "fgGreen", "fgYellow", "fgBlue", "fgMagenta", "fgCyan"}

	// CFgB ...
	CFgB = color.New(color.FgHiCyan, color.Bold).SprintFunc()

	// CFgD ...
	CFgD = color.New(color.FgHiCyan).SprintFunc()

	// GFgB ...
	GFgB = color.New(color.FgHiGreen, color.Bold).SprintFunc()

	// GFgD ...
	GFgD = color.New(color.FgHiGreen).SprintFunc()

	// MFgB ...
	MFgB = color.New(color.FgMagenta, color.Bold).SprintFunc()

	// MFgD ...
	MFgD = color.New(color.FgMagenta).SprintFunc()

	// RFgD ...
	RFgD = color.New(color.FgRed).SprintFunc()

	// RFgB ...
	RFgB = color.New(color.FgRed, color.Bold).SprintFunc()

	// WFgD ...
	WFgD = color.New(color.FgWhite).SprintFunc()

	// WFgB ...
	WFgB = color.New(color.FgWhite, color.Bold).SprintFunc()

	// YFgD ...
	YFgD = color.New(color.FgYellow).SprintFunc()

	// YFgB ...
	YFgB = color.New(color.FgYellow, color.Bold).SprintFunc()
)
