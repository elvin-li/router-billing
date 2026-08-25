package server

import "strings"

// csvCell neutralizes spreadsheet formula injection in CSV exports.
//
// Excel / LibreOffice / Google Sheets interpret cells beginning with
// '=', '+', '-', or '@' as formulas — and legacy DDE payloads like
// `=cmd|'/c calc'!A0` execute on open. Several exported columns carry
// text an end user (not the admin) controls: MAC labels come from the
// user-side /user/macs/label form, SMS bodies / gateway error strings
// come from external systems, and audit detail embeds both. Prefixing a
// single quote makes the cell render as literal text; the leading tab /
// CR check covers the same trick smuggled behind whitespace.
//
// Values that never start with those bytes (RFC3339 timestamps, decimal
// ids, normalized MACs) pass through unchanged, so wrapping every string
// column is safe.
func csvCell(s string) string {
	if s == "" {
		return s
	}
	switch s[0] {
	case '=', '+', '-', '@', '\t', '\r':
		return "'" + s
	}
	// A quoted-cell bypass: `"=..."` is unquoted by the consumer before
	// evaluation in some spreadsheet import paths. Also catch a formula
	// char hiding behind leading spaces.
	if trimmed := strings.TrimLeft(s, " "); trimmed != s && trimmed != "" {
		switch trimmed[0] {
		case '=', '+', '-', '@', '\t', '\r':
			return "'" + s
		}
	}
	return s
}
