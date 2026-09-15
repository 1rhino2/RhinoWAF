// Package rulesets embeds the default rule files and their data lists so a
// fresh binary detects out of the box with no config dir. An operator can
// point engine.rules_dir at their own directory to replace this set, or
// drop tuning files in extra_rules_dir to layer on top.
package rulesets

import "embed"

//go:embed *.rules data/*.txt
var FS embed.FS
