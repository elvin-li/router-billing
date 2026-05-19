package models

import (
	"regexp"
	"strings"
	"time"
)

// --- MAC ---

type MACStatus string

const (
	MACActive  MACStatus = "active"
	MACExpired MACStatus = "expired"
	MACBlocked MACStatus = "blocked"
)

type MAC struct {
	ID           int64     `json:"id"`
	Mac          string    `json:"mac"`
	Label        string    `json:"label"`
	Status       MACStatus `json:"status"`
	ExpiresAt    time.Time `json:"expires_at"`
	UserID       *int64    `json:"user_id,omitempty"`
	ScheduleJSON string    `json:"schedule_json,omitempty"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// --- Order ---

type OrderStatus string

const (
	OrderPending  OrderStatus = "pending"
	OrderPaid     OrderStatus = "paid"
	OrderFailed   OrderStatus = "failed"
	OrderExpired  OrderStatus = "expired"
	OrderRefunded OrderStatus = "refunded"
)

type Order struct {
	ID            int64       `json:"id"`
	OrderNo       string      `json:"order_no"`
	Mac           string      `json:"mac"`
	Plan          string      `json:"plan"`
	Days          int         `json:"days"`
	AmountCents   int         `json:"amount_cents"`
	Status        OrderStatus `json:"status"`
	PaymentMethod string      `json:"payment_method"`
	TradeNo       string      `json:"trade_no"`
	UserID        *int64      `json:"user_id,omitempty"`
	LastQueriedAt *time.Time  `json:"last_queried_at,omitempty"`
	PaidAt        *time.Time  `json:"paid_at,omitempty"`
	CreatedAt     time.Time   `json:"created_at"`
}

// --- User ---

type User struct {
	ID           int64  `json:"id"`
	Phone        string `json:"phone"`
	PasswordHash string `json:"-"`
	Suspended    bool   `json:"suspended"`
	// TOTPSecret is the confirmed base32 TOTP secret. Empty = 2FA off.
	TOTPSecret string `json:"-"`
	// TOTPPending is a freshly-generated secret waiting for the user to type
	// their first valid code. Cleared on confirm or replaced if the user
	// re-clicks "enable" before confirming.
	TOTPPending string `json:"-"`
	// NotifyExpiry controls whether this user receives the 套餐到期提醒
	// SMS from the background loop. Defaults to true. The user toggles it
	// in /user/me account preferences.
	NotifyExpiry bool      `json:"notify_expiry"`
	CreatedAt    time.Time `json:"created_at"`
	UpdatedAt    time.Time `json:"updated_at"`
}

// --- TrustedDevice ---

// TrustedDevice is one browser the user has marked "trust this device"
// after a successful 2FA verify. The presence of a matching, unexpired
// cookie on /user/login lets us skip the 2FA challenge — same trust model
// as "remember me" on GitHub / Google.
type TrustedDevice struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id"`
	Token     string    `json:"-"` // raw cookie value; never JSON'd
	Label     string    `json:"label"`
	ExpiresAt time.Time `json:"expires_at"`
	LastSeen  time.Time `json:"last_seen"`
	CreatedAt time.Time `json:"created_at"`
}

// --- TOTP Backup Codes ---

// BackupCode is one emergency single-use 2FA code. Stored bcrypt-hashed;
// `UsedAt` non-nil means it's been consumed and won't verify again.
type BackupCode struct {
	ID        int64      `json:"id"`
	UserID    int64      `json:"user_id"`
	CodeHash  string     `json:"-"`
	UsedAt    *time.Time `json:"used_at,omitempty"`
	CreatedAt time.Time  `json:"created_at"`
}

// --- PasswordReset ---

// PasswordReset is one outstanding SMS-issued reset code. Only one row per
// user is kept (issuing a new code deletes any prior).
type PasswordReset struct {
	ID        int64     `json:"id"`
	UserID    int64     `json:"user_id"`
	CodeHash  string    `json:"-"` // bcrypt of the 6-digit code
	Attempts  int       `json:"attempts"`
	ExpiresAt time.Time `json:"expires_at"`
	CreatedAt time.Time `json:"created_at"`
}

// --- Sighting ---

type Sighting struct {
	MAC       string    `json:"mac"`
	LastIP    string    `json:"last_ip"`
	Hostname  string    `json:"hostname"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

// --- Voucher ---

type Voucher struct {
	ID             int64      `json:"id"`
	Code           string     `json:"code"` // canonical, dash-less
	Days           int        `json:"days"`
	Label          string     `json:"label"`
	Batch          string     `json:"batch"`
	ExpiresAt      *time.Time `json:"expires_at,omitempty"`
	RedeemedAt     *time.Time `json:"redeemed_at,omitempty"`
	RedeemedByMac  string     `json:"redeemed_by_mac,omitempty"`
	RedeemedUserID *int64     `json:"redeemed_user_id,omitempty"`
	Revoked        bool       `json:"revoked"`
	CreatedAt      time.Time  `json:"created_at"`
}

// --- StatsDaily ---

type StatsDaily struct {
	Day          string    `json:"day"` // YYYY-MM-DD
	MacTotal     int       `json:"mac_total"`
	MacActive    int       `json:"mac_active"`
	UsersTotal   int       `json:"users_total"`
	RevenueCents int       `json:"revenue_cents"`
	PaidOrders   int       `json:"paid_orders"`
	SnapshotAt   time.Time `json:"snapshot_at"`
}

// --- Plan (DB-backed overlay over config) ---

type Plan struct {
	Key        string    `json:"key"`
	Label      string    `json:"label"`
	Days       int       `json:"days"`
	PriceCents int       `json:"price_cents"`
	SortOrder  int       `json:"sort_order"`
	Enabled    bool      `json:"enabled"`
	UpdatedAt  time.Time `json:"updated_at"`
}

// --- Validation ---

var (
	macRe   = regexp.MustCompile(`^[0-9A-Fa-f]{2}([:-]?[0-9A-Fa-f]{2}){5}$`)
	phoneRe = regexp.MustCompile(`^1[3-9]\d{9}$`)
)

// NormalizeMAC validates and converts to canonical AA:BB:CC:DD:EE:FF form.
func NormalizeMAC(s string) (string, bool) {
	s = strings.TrimSpace(s)
	if !macRe.MatchString(s) {
		return "", false
	}
	hex := strings.ToUpper(strings.NewReplacer(":", "", "-", "").Replace(s))
	if len(hex) != 12 {
		return "", false
	}
	parts := make([]string, 6)
	for i := 0; i < 6; i++ {
		parts[i] = hex[i*2 : i*2+2]
	}
	return strings.Join(parts, ":"), true
}

// ValidPhone matches Chinese mobile numbers (11 digits starting with 1[3-9]).
func ValidPhone(s string) bool {
	return phoneRe.MatchString(strings.TrimSpace(s))
}

// ValidPassword rejects passwords < 6 chars. Liberal otherwise.
func ValidPassword(p string) bool {
	return len(p) >= 6 && len(p) <= 72 // bcrypt limit 72
}
