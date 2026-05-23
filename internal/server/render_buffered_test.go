package server

import (
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

// TestRenderBuffersOnPartialFailure pins the v0.97 fix to render(): when
// ExecuteTemplate writes some bytes and *then* errors, the user must NOT
// see the partial output. Pre-v0.97 they got HTTP 200 + "<partial
// HTML>internal\n" because the implicit WriteHeader from the first Write
// beat http.Error's WriteHeader(500), and http.Error's "internal\n" body
// was appended to whatever the template had already written.
//
// The buffered render() collects output to a bytes.Buffer first; on
// error it never touches w except via http.Error, which now actually
// gets to set the 500 status because no bytes have leaked yet.
//
// This test installs a template that prints "ALPHA-" and then accesses
// a missing struct field (a hard error in html/template). With the old
// render() the body would contain "ALPHA-internal\n" with status 200.
// With the new render() the body is exactly "internal\n" with status 500.
func TestRenderBuffersOnPartialFailure(t *testing.T) {
	app := setupTestApp(t)

	// Add a template that writes some bytes, then errors mid-render. The
	// ".NoSuchField.Y" chain triggers the same kind of struct-field miss
	// that bit the dashboard pre-v0.96 — only this time we deliberately
	// trigger it to verify the surrounding handler is robust.
	if _, err := app.tpl.New("__partial_fail__").Parse(
		`ALPHA-{{.NoSuchField.Y}}-OMEGA`,
	); err != nil {
		t.Fatal(err)
	}

	rr := httptest.NewRecorder()
	app.render(rr, "__partial_fail__", struct{}{})
	res := rr.Result()
	body, _ := io.ReadAll(res.Body)

	if res.StatusCode != http.StatusInternalServerError {
		t.Errorf("expected 500 on template error, got %d (body=%q) — render() leaked an implicit 200",
			res.StatusCode, string(body))
	}
	if string(body) != "internal\n" {
		t.Errorf("expected exactly %q, got %q — render() leaked partial output before failing",
			"internal\n", string(body))
	}
	if strings.Contains(string(body), "ALPHA") {
		t.Errorf("partial-render leak: pre-error body content escaped to client; got %q", string(body))
	}
	// On error path http.Error sets text/plain. text/html would mean the
	// 200-path headers were set before the failure — i.e. unbuffered render.
	if ct := res.Header.Get("Content-Type"); strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type should not be text/html on error, got %q", ct)
	}
}

// TestRenderBuffersOnSuccess covers the happy path: a template that
// renders cleanly produces 200 + text/html + the rendered body, with
// the buffer-then-write path leaving no fingerprint.
func TestRenderBuffersOnSuccess(t *testing.T) {
	app := setupTestApp(t)
	if _, err := app.tpl.New("__ok__").Parse(`hello {{.Name}}`); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	app.render(rr, "__ok__", map[string]any{"Name": "world"})
	res := rr.Result()
	body, _ := io.ReadAll(res.Body)

	if res.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d", res.StatusCode)
	}
	if string(body) != "hello world" {
		t.Errorf("body = %q, want %q", string(body), "hello world")
	}
	if ct := res.Header.Get("Content-Type"); !strings.HasPrefix(ct, "text/html") {
		t.Errorf("Content-Type = %q, want text/html prefix", ct)
	}
}

// TestRenderMissingMapKeyIsZeroNotNoValue pins the v0.97 templating
// option missingkey=zero. Pre-v0.97 the default was "default", which
// renders missing map keys as the literal string "<no value>". That's
// the silent-bug shape the v0.96 dashboard fix mistakenly attributed
// the plan-sales bug to (see the test comment in
// admin_dashboard_plan_sales_test.go). It wasn't the cause there but it
// IS a real footgun for any template that takes map[string]any data —
// switching to "zero" makes naked {{.MissingKey}} render as "" instead.
func TestRenderMissingMapKeyIsZeroNotNoValue(t *testing.T) {
	app := setupTestApp(t)
	if _, err := app.tpl.New("__map_miss__").Parse(`X={{.MissingKey}}Y`); err != nil {
		t.Fatal(err)
	}
	rr := httptest.NewRecorder()
	app.render(rr, "__map_miss__", map[string]any{"OtherKey": "v"})
	res := rr.Result()
	body, _ := io.ReadAll(res.Body)

	if res.StatusCode != http.StatusOK {
		t.Errorf("expected 200, got %d (body=%q)", res.StatusCode, string(body))
	}
	if strings.Contains(string(body), "<no value>") {
		t.Errorf("map-key miss rendered '<no value>'; missingkey=zero option is not effective. body=%q", string(body))
	}
	if string(body) != "X=Y" {
		t.Errorf("body = %q, want %q (missing key should render as empty string)", string(body), "X=Y")
	}
}
