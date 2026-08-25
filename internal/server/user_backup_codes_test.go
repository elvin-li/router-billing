package server

import (
	"context"
	"net/http"
	"net/url"
	"strings"
	"testing"

	"golang.org/x/crypto/bcrypt"
)

// enrollUser2FA runs the user through register → 2FA enroll → confirm so the
// caller can focus on backup-code behavior. Returns the cookie jar with
// rb_user + rb_csrf, and the 10 plaintext backup codes scraped from the
// confirmation response page.
func enrollUser2FA(t *testing.T, h http.Handler, app *App, phone, password string) (jar map[string]string, codes []string) {
	t.Helper()
	jar = registerAndLogin(t, h, phone, password)
	csrf := jar[csrfCookieName]
	do(t, h, "POST", "/user/2fa/begin", url.Values{"_csrf": {csrf}}, jar)
	code := validTOTPForUser(t, app, phone)
	_, body := do(t, h, "POST", "/user/2fa/confirm",
		url.Values{"_csrf": {csrf}, "code": {code}}, jar)
	codes = scrapeBackupCodes(t, body)
	return
}

// scrapeBackupCodes pulls the 10 codes out of the rendered page. The template
// puts each in <code>XXXXXXXX</code> within .codes-grid.
func scrapeBackupCodes(t *testing.T, html string) []string {
	t.Helper()
	const open = "<code>"
	const close = "</code>"
	var out []string
	rest := html
	for {
		i := strings.Index(rest, open)
		if i < 0 {
			break
		}
		rest = rest[i+len(open):]
		j := strings.Index(rest, close)
		if j < 0 {
			break
		}
		token := rest[:j]
		rest = rest[j+len(close):]
		if looksLikeBackupCode(token) {
			out = append(out, token)
		}
	}
	if len(out) != 10 {
		t.Fatalf("expected 10 backup codes; scraped %d from: %s", len(out), truncate(html, 600))
	}
	return out
}

func TestBackupCodeGeneratorShape(t *testing.T) {
	codes, err := generateBackupCodes(10)
	if err != nil {
		t.Fatal(err)
	}
	if len(codes) != 10 {
		t.Fatalf("len = %d", len(codes))
	}
	seen := map[string]bool{}
	for _, c := range codes {
		if len(c) != backupCodeLen {
			t.Errorf("code %q wrong length", c)
		}
		for _, r := range c {
			if !strings.ContainsRune(backupCodeAlpha, r) {
				t.Errorf("code %q has rune %q outside the alphabet", c, r)
			}
		}
		if seen[c] {
			t.Errorf("duplicate backup code: %q (extremely unlikely)", c)
		}
		seen[c] = true
	}
}

func TestLooksLikeBackupCode(t *testing.T) {
	cases := []struct {
		in   string
		want bool
	}{
		{"", false},
		{"123456", false},   // 6-digit TOTP
		{"ABCD1234", true},  // canonical
		{"abcd1234", true},  // lowercase OK (normalized)
		{"abcd-1234", true}, // dash OK
		{"ABCD 1234", true}, // space OK
		{strings.Repeat("X", backupCodeMaxLen+1), false}, // too long
		{"abc!1234", false}, // non-alphanumeric
		{strings.Repeat("A", backupCodeMinLen-1), false}, // too short
	}
	for _, c := range cases {
		if got := looksLikeBackupCode(c.in); got != c.want {
			t.Errorf("looksLikeBackupCode(%q) = %v, want %v", c.in, got, c.want)
		}
	}
}

func TestNormalizeBackupCode(t *testing.T) {
	cases := []struct{ in, want string }{
		{"abcd-1234", "ABCD1234"},
		{"  abc 123  ", "ABC123"},
		{"X", "X"},
	}
	for _, c := range cases {
		if got := normalizeBackupCode(c.in); got != c.want {
			t.Errorf("normalizeBackupCode(%q) = %q, want %q", c.in, got, c.want)
		}
	}
}

func TestEnrollmentGeneratesTenStoredBcryptHashes(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	_, plain := enrollUser2FA(t, h, app, "13800139020", "enroll-pw")

	u, _ := app.DB.GetUserByPhone(context.Background(), "13800139020")
	stored, _ := app.DB.ListBackupCodes(context.Background(), u.ID)
	if len(stored) != 10 {
		t.Fatalf("expected 10 stored codes; got %d", len(stored))
	}

	// Each plaintext should bcrypt-match exactly one stored hash.
	for _, p := range plain {
		matches := 0
		for _, s := range stored {
			if bcrypt.CompareHashAndPassword([]byte(s.CodeHash), []byte(p)) == nil {
				matches++
			}
		}
		if matches != 1 {
			t.Errorf("plaintext %q matched %d stored hashes", p, matches)
		}
	}
}

func TestBackupCodeUnlocksLoginWhenTOTPFails(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	_, plain := enrollUser2FA(t, h, app, "13800139021", "unlock-pw")

	// Fresh password-only login → pending cookie.
	res, _ := do(t, h, "POST", "/user/login",
		url.Values{"phone": {"13800139021"}, "password": {"unlock-pw"}}, nil)
	pending := cookieJar(res)
	res2, _ := do(t, h, "GET", "/user/login/2fa", nil, pending)
	for k, v := range cookieJar(res2) {
		pending[k] = v
	}
	csrf := pending[csrfCookieName]

	// Submit a backup code instead of TOTP — should succeed.
	res3, _ := do(t, h, "POST", "/user/login/2fa",
		url.Values{"code": {plain[0]}, "_csrf": {csrf}}, pending)
	if res3.StatusCode != 303 {
		t.Fatalf("backup-code login: %d", res3.StatusCode)
	}
	if cookieJar(res3)[userCookieName] == "" {
		t.Error("rb_user should be set after a valid backup code")
	}

	// That code is now used — the same code on a fresh login attempt fails.
	res4, _ := do(t, h, "POST", "/user/login",
		url.Values{"phone": {"13800139021"}, "password": {"unlock-pw"}}, nil)
	pending2 := cookieJar(res4)
	res5, _ := do(t, h, "GET", "/user/login/2fa", nil, pending2)
	for k, v := range cookieJar(res5) {
		pending2[k] = v
	}
	csrf2 := pending2[csrfCookieName]
	res6, _ := do(t, h, "POST", "/user/login/2fa",
		url.Values{"code": {plain[0]}, "_csrf": {csrf2}}, pending2)
	if res6.StatusCode != 200 {
		// expect re-render with error, NOT redirect-with-session
		t.Errorf("reused backup code should fail; got %d", res6.StatusCode)
	}
	if cookieJar(res6)[userCookieName] != "" {
		t.Error("reused backup code must not issue rb_user")
	}

	// A different unused backup code still works.
	res7, _ := do(t, h, "POST", "/user/login/2fa",
		url.Values{"code": {plain[1]}, "_csrf": {csrf2}}, pending2)
	if res7.StatusCode != 303 {
		t.Errorf("second backup code: %d", res7.StatusCode)
	}
}

func TestBackupCodeAcceptsDashedAndLowercase(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	_, plain := enrollUser2FA(t, h, app, "13800139022", "case-pw")

	res, _ := do(t, h, "POST", "/user/login",
		url.Values{"phone": {"13800139022"}, "password": {"case-pw"}}, nil)
	pending := cookieJar(res)
	res2, _ := do(t, h, "GET", "/user/login/2fa", nil, pending)
	for k, v := range cookieJar(res2) {
		pending[k] = v
	}
	csrf := pending[csrfCookieName]

	// Format the code as "abcd-1234" lowercase + dashed.
	c := plain[0]
	dashed := strings.ToLower(c[:4] + "-" + c[4:])

	res3, _ := do(t, h, "POST", "/user/login/2fa",
		url.Values{"code": {dashed}, "_csrf": {csrf}}, pending)
	if res3.StatusCode != 303 {
		t.Fatalf("lowercase-dashed backup code: %d", res3.StatusCode)
	}
}

func TestRegenerateCodesInvalidatesOldOnes(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar, oldCodes := enrollUser2FA(t, h, app, "13800139023", "regen-pw")
	csrf := jar[csrfCookieName]

	// Regenerate.
	_, body := do(t, h, "POST", "/user/2fa/regenerate-codes",
		url.Values{"_csrf": {csrf}}, jar)
	newCodes := scrapeBackupCodes(t, body)

	// No overlap (probabilistically guaranteed — alphabet^8 = 1e12).
	oldSet := map[string]bool{}
	for _, c := range oldCodes {
		oldSet[c] = true
	}
	for _, c := range newCodes {
		if oldSet[c] {
			t.Errorf("regenerated code %q collides with an old one", c)
		}
	}

	// Old codes no longer work for login.
	res, _ := do(t, h, "POST", "/user/login",
		url.Values{"phone": {"13800139023"}, "password": {"regen-pw"}}, nil)
	pending := cookieJar(res)
	res2, _ := do(t, h, "GET", "/user/login/2fa", nil, pending)
	for k, v := range cookieJar(res2) {
		pending[k] = v
	}
	csrf2 := pending[csrfCookieName]

	res3, _ := do(t, h, "POST", "/user/login/2fa",
		url.Values{"code": {oldCodes[0]}, "_csrf": {csrf2}}, pending)
	if res3.StatusCode != 200 {
		t.Errorf("old code should fail after regenerate; got status %d", res3.StatusCode)
	}
	if cookieJar(res3)[userCookieName] != "" {
		t.Error("old code must not issue rb_user after regenerate")
	}

	// A new code works.
	res4, _ := do(t, h, "POST", "/user/login/2fa",
		url.Values{"code": {newCodes[0]}, "_csrf": {csrf2}}, pending)
	if res4.StatusCode != 303 {
		t.Errorf("new code: %d", res4.StatusCode)
	}
}

func TestMarkBackupCodeUsedReportsConsumption(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	_, _ = enrollUser2FA(t, h, app, "13800139028", "consume-pw")
	u, _ := app.DB.GetUserByPhone(context.Background(), "13800139028")
	rows, _ := app.DB.UnusedBackupCodes(context.Background(), u.ID)
	if len(rows) == 0 {
		t.Fatal("setup: no backup codes")
	}
	id := rows[0].ID

	consumed, err := app.DB.MarkBackupCodeUsed(context.Background(), id)
	if err != nil || !consumed {
		t.Fatalf("first mark: consumed=%v err=%v", consumed, err)
	}
	// Second mark of the same row must report NOT consumed — this is what
	// stops two concurrent logins from both spending one code.
	consumed, err = app.DB.MarkBackupCodeUsed(context.Background(), id)
	if err != nil {
		t.Fatal(err)
	}
	if consumed {
		t.Error("already-used code reported consumed again")
	}
}

func TestBackupCodeConcurrentUseSpendsExactlyOnce(t *testing.T) {
	// Two logins racing on the same backup code: both may read the row as
	// unused, but only the one whose conditional UPDATE lands may pass.
	app := setupTestApp(t)
	h := app.Routes()
	_, plain := enrollUser2FA(t, h, app, "13800139029", "race-pw")
	u, _ := app.DB.GetUserByPhone(context.Background(), "13800139029")

	results := make(chan bool, 2)
	for i := 0; i < 2; i++ {
		go func() {
			ok, err := app.verifyAndConsumeBackupCode(context.Background(), u.ID, plain[0])
			if err != nil {
				t.Errorf("verify: %v", err)
			}
			results <- ok
		}()
	}
	successes := 0
	for i := 0; i < 2; i++ {
		if <-results {
			successes++
		}
	}
	if successes != 1 {
		t.Errorf("backup code spent %d times; want exactly 1", successes)
	}
}

func TestDisableAlsoClearsBackupCodes(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar, _ := enrollUser2FA(t, h, app, "13800139024", "wipe-pw")
	csrf := jar[csrfCookieName]

	// Disable 2FA fully.
	code := validTOTPForUser(t, app, "13800139024")
	do(t, h, "POST", "/user/2fa/disable",
		url.Values{"_csrf": {csrf}, "password": {"wipe-pw"}, "code": {code}}, jar)

	u, _ := app.DB.GetUserByPhone(context.Background(), "13800139024")
	stored, _ := app.DB.ListBackupCodes(context.Background(), u.ID)
	if len(stored) != 0 {
		t.Errorf("disabling 2fa should wipe backup codes; got %d", len(stored))
	}
}

func TestRegenerateCodesRejectedWhenNotEnrolled(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar := registerAndLogin(t, h, "13800139025", "noenr-pw")
	csrf := jar[csrfCookieName]

	res, _ := do(t, h, "POST", "/user/2fa/regenerate-codes",
		url.Values{"_csrf": {csrf}}, jar)
	if res.StatusCode != 303 {
		t.Fatalf("status: %d", res.StatusCode)
	}
	if !strings.Contains(res.Header.Get("Location"), "2fa_not_enrolled") {
		t.Errorf("redirect: %s", res.Header.Get("Location"))
	}
}

func TestUser2FAPageShowsBackupCodeCount(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	jar, _ := enrollUser2FA(t, h, app, "13800139026", "count-pw")

	_, body := do(t, h, "GET", "/user/2fa", nil, jar)
	if !strings.Contains(body, "10 / 10") {
		t.Errorf("settings page should show '10 / 10'; body=%s", truncate(body, 500))
	}
}

func TestBackupCodeLoginRespectsAttemptCap(t *testing.T) {
	app := setupTestApp(t)
	h := app.Routes()
	_, _ = enrollUser2FA(t, h, app, "13800139027", "cap-pw")

	res, _ := do(t, h, "POST", "/user/login",
		url.Values{"phone": {"13800139027"}, "password": {"cap-pw"}}, nil)
	pending := cookieJar(res)
	res2, _ := do(t, h, "GET", "/user/login/2fa", nil, pending)
	for k, v := range cookieJar(res2) {
		pending[k] = v
	}
	csrf := pending[csrfCookieName]

	// 6 wrong attempts — each attempt is bcrypt-walked over all 10 backup
	// codes, so this is somewhat slow. We use a deliberately-wrong code that
	// also looks like a backup code to exercise both verifier paths.
	var locLast string
	for i := 0; i < 6; i++ {
		r, _ := do(t, h, "POST", "/user/login/2fa",
			url.Values{"code": {"WRONGCD1"}, "_csrf": {csrf}}, pending)
		locLast = r.Header.Get("Location")
	}
	if !strings.Contains(locLast, "2fa_locked") && !strings.Contains(locLast, "2fa_expired") {
		t.Errorf("expected lockout; got %s", locLast)
	}
}
