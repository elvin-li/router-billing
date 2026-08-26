package server

import "unicode/utf8"

// truncateRunes caps s at max bytes WITHOUT splitting a multi-byte UTF-8
// sequence: if the cut lands mid-rune, it backs up to the previous rune
// boundary. Every free-text cap in the handlers (labels, notes, refund
// reasons, SMS bodies, audit notes) used a raw byte slice s[:n], which on
// Chinese input regularly produced invalid UTF-8 — stored verbatim in
// SQLite, rendered as U+FFFD by html/template and JSON exports, and emitted
// as raw invalid bytes in CSV exports.
//
// max is still a byte budget (that's what the DB caps care about), so ASCII
// behavior is unchanged and the result is never longer than max bytes.
func truncateRunes(s string, max int) string {
	if max <= 0 {
		return ""
	}
	if len(s) <= max {
		return s
	}
	cut := max
	// A UTF-8 continuation byte is 0b10xxxxxx; back up (at most 3 steps)
	// until cut sits on a rune start so we never emit a torn sequence.
	for cut > 0 && !utf8.RuneStart(s[cut]) {
		cut--
	}
	return s[:cut]
}
