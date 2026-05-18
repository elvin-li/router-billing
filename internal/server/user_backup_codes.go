package server

import (
	"context"
	"crypto/rand"
	"log"
	"net/http"
	"strings"

	"golang.org/x/crypto/bcrypt"

	"router-billing/internal/models"
)

// TOTP backup codes — single-use 8-char alphanumeric codes that act as
// emergency replacements for the 6-digit TOTP. Generated:
//
//   - 10 at a time on first successful 2FA enrollment (one-time view), and
//   - on demand from /user/2fa via "重新生成备用码" (wipes the old 10).
//
// At /user/login/2fa we try the user's TOTP secret first, then fall back to
// the backup-code path if the input length looks like a backup code (8
// alphanumerics rather than 6 digits). Backup codes don't bypass the per-
// pending-token attempt cap.
const (
	backupCodeCount   = 10
	backupCodeLen     = 8
	backupCodeAlpha   = "ABCDEFGHJKLMNPQRSTUVWXYZ23456789" // visually unambiguous (no 0/O/1/I/L)
	backupCodeMinLen  = 8                                  // distinguishes backup from a 6-digit TOTP
	backupCodeMaxLen  = 20                                 // generous, paste-friendly
	backupCodeBcrypt  = bcrypt.DefaultCost
	backupCodeSession = "user_backup_codes_show" // key in session-less query for one-time display
)

// generateBackupCodes returns N fresh codes. Each is uniformly drawn from
// the unambiguous alphabet, so collisions are negligible (32^8 = ~1e12).
func generateBackupCodes(n int) ([]string, error) {
	if n <= 0 {
		n = backupCodeCount
	}
	out := make([]string, n)
	buf := make([]byte, backupCodeLen)
	for i := 0; i < n; i++ {
		if _, err := rand.Read(buf); err != nil {
			return nil, err
		}
		code := make([]byte, backupCodeLen)
		for j, b := range buf {
			code[j] = backupCodeAlpha[int(b)%len(backupCodeAlpha)]
		}
		out[i] = string(code)
	}
	return out, nil
}

// hashBackupCodes wraps each plaintext in bcrypt.
func hashBackupCodes(codes []string) ([]string, error) {
	out := make([]string, len(codes))
	for i, c := range codes {
		h, err := bcrypt.GenerateFromPassword([]byte(c), backupCodeBcrypt)
		if err != nil {
			return nil, err
		}
		out[i] = string(h)
	}
	return out, nil
}

// looksLikeBackupCode tells the login-2fa handler whether to attempt the
// backup-code path. We're deliberately lenient on case so users can type as
// they wish; verifyBackupCode normalizes to upper.
func looksLikeBackupCode(s string) bool {
	s = normalizeBackupCode(s)
	if len(s) < backupCodeMinLen || len(s) > backupCodeMaxLen {
		return false
	}
	for _, r := range s {
		if !(r >= 'A' && r <= 'Z') && !(r >= '0' && r <= '9') {
			return false
		}
	}
	return true
}

// normalizeBackupCode upper-cases and strips spaces/dashes so "abcd-ef12"
// and "abcdef12" both match.
func normalizeBackupCode(s string) string {
	return strings.ToUpper(strings.Map(func(r rune) rune {
		switch r {
		case ' ', '-', '\t':
			return -1
		}
		return r
	}, s))
}

// verifyAndConsumeBackupCode checks `code` against every unused backup code
// for `userID`. Returns true and marks the row used on success. Always walks
// every row so timing doesn't reveal which slot matched (bcrypt itself is
// constant-time per call).
func (a *App) verifyAndConsumeBackupCode(ctx context.Context, userID int64, code string) (bool, error) {
	candidate := []byte(normalizeBackupCode(code))
	rows, err := a.DB.UnusedBackupCodes(ctx, userID)
	if err != nil {
		return false, err
	}
	matched := int64(0)
	for _, r := range rows {
		if bcrypt.CompareHashAndPassword([]byte(r.CodeHash), candidate) == nil {
			matched = r.ID
		}
	}
	if matched == 0 {
		return false, nil
	}
	if err := a.DB.MarkBackupCodeUsed(ctx, matched); err != nil {
		return false, err
	}
	return true, nil
}

// renderBackupCodesOnce displays the freshly-generated plaintexts. Called
// after /user/2fa/confirm and /user/2fa/regenerate-codes. The codes only
// exist in process memory at this moment — they're not stored in plaintext
// anywhere — so a refresh of the page won't show them again.
func (a *App) renderBackupCodesOnce(w http.ResponseWriter, r *http.Request, user *models.User, codes []string) {
	a.render(w, "user_2fa_codes.html", a.userCtx(r, "2fa", map[string]any{
		"User":  user,
		"Codes": codes,
	}))
}

// generateAndStoreBackupCodes is the shared helper called from both the
// confirm-enrollment and regenerate paths. Returns the plaintexts so the
// caller can render them — they're never persisted in cleartext.
func (a *App) generateAndStoreBackupCodes(ctx context.Context, userID int64) ([]string, error) {
	plain, err := generateBackupCodes(backupCodeCount)
	if err != nil {
		return nil, err
	}
	hashes, err := hashBackupCodes(plain)
	if err != nil {
		return nil, err
	}
	if err := a.DB.ReplaceBackupCodes(ctx, userID, hashes); err != nil {
		return nil, err
	}
	return plain, nil
}

// POST /user/2fa/regenerate-codes — wipes the existing 10 codes and shows
// fresh ones. Only usable when 2FA is fully enrolled.
func (a *App) handleUser2FARegenerateCodes(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Redirect(w, r, "/user/2fa", http.StatusSeeOther)
		return
	}
	uid := a.currentUserID(r)
	user, err := a.DB.GetUser(r.Context(), uid)
	if err != nil || user == nil {
		http.Redirect(w, r, "/user/login", http.StatusSeeOther)
		return
	}
	if user.TOTPSecret == "" {
		http.Redirect(w, r, "/user/2fa?err=2fa_not_enrolled", http.StatusSeeOther)
		return
	}
	codes, err := a.generateAndStoreBackupCodes(r.Context(), uid)
	if err != nil {
		log.Printf("regenerate backup codes %d: %v", uid, err)
		http.Redirect(w, r, "/user/2fa?err=internal", http.StatusSeeOther)
		return
	}
	a.DB.Audit(r.Context(), "user:"+user.Phone, "2fa_backup_codes_regenerated", "", "ip="+clientIP(r))
	a.renderBackupCodesOnce(w, r, user, codes)
}
