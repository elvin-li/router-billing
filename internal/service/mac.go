package service

import (
	"context"
	"fmt"
	"log"
	"sync"
	"time"

	"router-billing/internal/db"
	"router-billing/internal/firewall"
	"router-billing/internal/models"
)

// MACService is the only place that mutates both DB and firewall together.
//
// FW is the firewall.API interface (not *firewall.Manager) so tests can
// substitute a fake and so a future iptables backend slots in without
// touching this file.
type MACService struct {
	DB *db.DB
	FW firewall.API

	// mu serializes every composite (DB state + firewall set) operation.
	//
	// The DB layer is transactional and both firewall backends serialize
	// their own commands, but WITHOUT this lock the pairing between the two
	// was not atomic, and the concurrent actors (payment finalizer, expiry
	// scheduler, minute schedule-enforcer, admin handlers) could interleave
	// into firewall state that contradicts the DB until the next resync:
	//
	//   - Resync read the active list, a grant then committed+FW.Add'ed,
	//     and Resync's full rebuild flushed the fresh MAC out of the set;
	//   - ExpireDue flipped rows to expired, a payment re-activated one of
	//     them (DB + FW.Add), and ExpireDue's follow-up FW.Remove yanked
	//     the just-paid MAC offline;
	//   - the schedule enforcer listed active MACs, an admin Revoke landed
	//     (DB blocked + FW.Remove), and the enforcer's FW.Add put the
	//     blocked MAC back online for the rest of its window.
	mu sync.Mutex
}

func New(d *db.DB, fw firewall.API) *MACService {
	return &MACService{DB: d, FW: fw}
}

// scheduleAllowsNow reports whether the row's time-of-day schedule permits
// the MAC to be online at `now`. No schedule means "always allowed"; parse
// errors fail open (allow) — matching EnforceSchedules and resyncLocked, so
// a corrupt schedule_json can never lock a paying customer out.
func scheduleAllowsNow(m *models.MAC, now time.Time) bool {
	if m == nil || m.ScheduleJSON == "" {
		return true
	}
	sched, err := models.ParseSchedule(m.ScheduleJSON)
	if err != nil {
		return true
	}
	return sched.Active(now)
}

// grantFirewallAdd is the firewall half of every grant/extend: add the MAC
// when its schedule window is open, defensively remove it when closed.
//
// Pre-v0.119 every grant path called FW.Add unconditionally, so paying for /
// extending a MAC whose time-of-day schedule window was CLOSED put the
// device online outside its allowed hours until the next minute tick of
// EnforceSchedules yanked it — the exact class v0.108 fixed for resync and
// v0.110 for ApplyScheduleNow, left over in the grant paths. Caller must
// hold s.mu.
func (s *MACService) grantFirewallAdd(ctx context.Context, m *models.MAC) error {
	if scheduleAllowsNow(m, time.Now()) {
		return s.FW.Add(ctx, m.Mac)
	}
	log.Printf("grant %s: schedule window closed — not adding to firewall (schedule=%s)", m.Mac, m.ScheduleJSON)
	return s.FW.Remove(ctx, m.Mac)
}

// GrantFromOrder adds days to MAC's expiry then puts it into the firewall set.
// If the order is linked to a user, that user becomes the MAC's owner.
//
// Returns an error ONLY if the DB grant failed (i.e. nothing durable
// happened and the caller may safely retry the whole grant). A firewall
// failure after the DB committed is NOT an error: the DB is the source of
// truth for the mac_paid set, so we attempt an immediate Resync and
// otherwise log loudly. Pre-v0.106 the fw error bubbled up as a webhook
// 500 whose PSP retries then no-oped (order already paid), so the failed
// nft add was never retried anyway — and the paid signal/audit/notify were
// all skipped.
func (s *MACService) GrantFromOrder(ctx context.Context, o *models.Order) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	label := fmt.Sprintf("paid-%s", o.Plan)
	m, err := s.DB.UpsertMAC(ctx, o.Mac, label, o.Days, o.UserID)
	if err != nil {
		return fmt.Errorf("upsert mac: %w", err)
	}
	if err := s.grantFirewallAdd(ctx, m); err != nil {
		log.Printf("warn: firewall add %s: %v — attempting resync", m.Mac, err)
		if rerr := s.resyncLocked(ctx); rerr != nil {
			log.Printf("ERROR: firewall resync after failed add %s: %v (paid MAC offline until next resync)", m.Mac, rerr)
		}
	}
	log.Printf("granted %s for %d days (until %s) from order %s", m.Mac, o.Days, m.ExpiresAt.Format("2006-01-02"), o.OrderNo)
	return nil
}

// GrantFromVoucher is GrantFromOrder's sibling for voucher redemptions.
// By the time it runs the voucher is already consumed, so it uses the same
// error contract: an error means NOTHING durable happened (the caller may
// safely un-redeem the voucher and let the user retry), while a
// firewall-only failure after the DB committed is logged + resynced but
// NOT surfaced — the DB is the source of truth and Extend's hard-fail
// semantics would report failure for a grant that actually landed.
func (s *MACService) GrantFromVoucher(ctx context.Context, mac, label string, days int, userID *int64) (*models.MAC, error) {
	// Same service-level lock as every other composite DB+firewall op —
	// the v0.110 serialization pass covered GrantFromOrder but missed this
	// sibling, so a redemption's FW.Add could land between a concurrent
	// Resync's active-list read and its full set rebuild and be flushed
	// straight back out of the kernel set (redeemed customer offline until
	// the next reconcile).
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.DB.UpsertMAC(ctx, mac, label, days, userID)
	if err != nil {
		return nil, fmt.Errorf("upsert mac: %w", err)
	}
	if err := s.grantFirewallAdd(ctx, m); err != nil {
		log.Printf("warn: firewall add %s (voucher): %v — attempting resync", m.Mac, err)
		if rerr := s.resyncLocked(ctx); rerr != nil {
			log.Printf("ERROR: firewall resync after failed add %s: %v (granted MAC offline until next resync)", m.Mac, rerr)
		}
	}
	log.Printf("granted %s for %d days (until %s) from voucher", m.Mac, days, m.ExpiresAt.Format("2006-01-02"))
	return m, nil
}

// Extend is the admin-manual version of GrantFromOrder.
func (s *MACService) Extend(ctx context.Context, mac, label string, days int, userID *int64) (*models.MAC, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.DB.UpsertMAC(ctx, mac, label, days, userID)
	if err != nil {
		return nil, err
	}
	if err := s.grantFirewallAdd(ctx, m); err != nil {
		return nil, err
	}
	return m, nil
}

// ExtendOwned extends a MAC only while it is still owned by ownerID, then
// re-adds it to the firewall set. Returns (nil, nil) when the MAC no longer
// exists or has been transferred to another user — callers treat that as
// "skipped", not an error. Used by the user-grant fan-outs so a concurrent
// device transfer can't be clobbered back to the granted user.
func (s *MACService) ExtendOwned(ctx context.Context, mac, label string, days int, ownerID int64) (*models.MAC, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.DB.ExtendMACOwned(ctx, mac, label, days, ownerID)
	if err != nil || m == nil {
		return nil, err
	}
	if err := s.grantFirewallAdd(ctx, m); err != nil {
		return nil, err
	}
	return m, nil
}

// Revoke marks blocked + drops from firewall set.
func (s *MACService) Revoke(ctx context.Context, mac string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.DB.SetMACStatus(ctx, mac, models.MACBlocked); err != nil {
		return err
	}
	return s.removeWithResyncFallback(ctx, mac, "revoke")
}

// Delete removes from DB + firewall.
func (s *MACService) Delete(ctx context.Context, mac string) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if err := s.DB.DeleteMAC(ctx, mac); err != nil {
		return err
	}
	return s.removeWithResyncFallback(ctx, mac, "delete")
}

// removeWithResyncFallback drops one MAC from the firewall set and, when
// that fails, immediately falls back to a full resync (rebuild from DB) —
// the same self-heal pattern grants use for a failed Add.
//
// Pre-v0.119 a transient FW.Remove failure (nft timeout under load, EINTR)
// during Revoke/Delete surfaced as an error but left the kernel set
// UNCHANGED: the DB said blocked/deleted while the device kept full
// internet access for up to an hour until the periodic reconcile — a rule
// leak after revoke. The DB write has already committed by the time this
// runs, so a successful resync converges the kernel to the truth and the
// operation reports success. Caller must hold s.mu.
func (s *MACService) removeWithResyncFallback(ctx context.Context, mac, op string) error {
	err := s.FW.Remove(ctx, mac)
	if err == nil {
		return nil
	}
	log.Printf("warn: firewall remove %s (%s): %v — attempting resync", mac, op, err)
	if rerr := s.resyncLocked(ctx); rerr != nil {
		return fmt.Errorf("firewall remove %s: %w (resync fallback also failed: %v — device may stay online until next resync)", mac, err, rerr)
	}
	return nil
}

// Replace transfers a user's remaining time from oldMac to newMac.
// Both DB row and firewall set are updated atomically.
func (s *MACService) Replace(ctx context.Context, userID int64, oldMac, newMac, label string) (*models.MAC, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.DB.ReplaceMAC(ctx, userID, oldMac, newMac, label)
	if err != nil {
		return nil, err
	}
	if err := s.FW.Remove(ctx, oldMac); err != nil {
		log.Printf("warn: firewall remove %s during replace: %v", oldMac, err)
	}
	if err := s.FW.Add(ctx, newMac); err != nil {
		return nil, fmt.Errorf("firewall add %s: %w", newMac, err)
	}
	return m, nil
}

// Resync rebuilds the firewall set from active MACs in DB.
//
// MACs carrying a time-of-day schedule are only included while their
// window is open — otherwise a resync (startup, admin-triggered, or the
// periodic reconcile) would grant a schedule-blocked device access until
// the next EnforceSchedules tick removed it again.
func (s *MACService) Resync(ctx context.Context) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.resyncLocked(ctx)
}

// resyncLocked is Resync's body. Caller must hold s.mu — the read of the
// active list and the full set rebuild must be one critical section, or a
// grant landing in between gets flushed out of the kernel set.
func (s *MACService) resyncLocked(ctx context.Context) error {
	macs, err := s.DB.ListActiveMACs(ctx)
	if err != nil {
		return err
	}
	now := time.Now()
	out := make([]string, 0, len(macs))
	for _, m := range macs {
		if m.ScheduleJSON != "" {
			sched, err := models.ParseSchedule(m.ScheduleJSON)
			if err == nil && !sched.Active(now) {
				continue
			}
			// Parse errors fail open (include the MAC) — matching
			// EnforceSchedules, which also skips unparseable schedules.
		}
		out = append(out, m.Mac)
	}
	return s.FW.Sync(ctx, out)
}

// EnforceSchedules runs forever, every minute applying any time-of-day
// schedules attached to active MACs. Adds to the firewall set when the
// schedule window opens, removes when it closes. Does NOT touch DB status.
func (s *MACService) EnforceSchedules(ctx context.Context) {
	t := time.NewTicker(time.Minute)
	defer t.Stop()
	s.enforceSchedulesOnce(ctx)
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			s.enforceSchedulesOnce(ctx)
		}
	}
}

func (s *MACService) enforceSchedulesOnce(ctx context.Context) {
	s.mu.Lock()
	defer s.mu.Unlock()
	now := time.Now()
	macs, err := s.DB.ListActiveMACs(ctx)
	if err != nil {
		// Log — a silent return here hid DB trouble from the operator while
		// schedule enforcement quietly stopped working.
		log.Printf("schedule: list active MACs: %v", err)
		return
	}
	for _, m := range macs {
		if m.ScheduleJSON == "" {
			continue
		}
		sched, err := models.ParseSchedule(m.ScheduleJSON)
		if err != nil {
			log.Printf("schedule: parse %s: %v", m.Mac, err)
			continue
		}
		if sched.Active(now) {
			if err := s.FW.Add(ctx, m.Mac); err != nil {
				log.Printf("schedule: add %s: %v", m.Mac, err)
			}
		} else {
			if err := s.FW.Remove(ctx, m.Mac); err != nil {
				log.Printf("schedule: remove %s: %v", m.Mac, err)
			}
		}
	}
}

// ApplyScheduleNow immediately reconciles one MAC's firewall membership
// after its schedule changed (saved or cleared), instead of waiting for the
// next minute tick. sched should be the just-persisted schedule; a zero
// (empty) schedule means "no restriction".
//
// Runs under the service lock so the eligibility check and the firewall
// write are one atomic step — the pre-v0.110 server-side version re-read
// the row and then called FW.Add unlocked, so a Revoke/Delete/expiry
// landing in between was overwritten and the ineligible MAC came back
// online until the next resync.
func (s *MACService) ApplyScheduleNow(ctx context.Context, mac string, sched models.MacSchedule) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	m, err := s.DB.GetMAC(ctx, mac)
	if err != nil {
		return err
	}
	// Never let a schedule write resurrect a blocked/expired/deleted MAC:
	// remove defensively, mirroring what the minute enforcer + resync
	// would converge to.
	if m == nil || m.Status != models.MACActive || !m.ExpiresAt.After(time.Now()) {
		return s.FW.Remove(ctx, mac)
	}
	if sched.IsEmpty() || sched.Active(time.Now()) {
		return s.FW.Add(ctx, mac)
	}
	return s.FW.Remove(ctx, mac)
}

// ExpireDue marks expired DB rows and yanks them from firewall.
func (s *MACService) ExpireDue(ctx context.Context) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	expired, err := s.DB.ExpireDueMACs(ctx)
	if err != nil {
		return 0, err
	}
	removeFailed := false
	for _, m := range expired {
		if err := s.FW.Remove(ctx, m); err != nil {
			log.Printf("warn: firewall remove %s: %v", m, err)
			removeFailed = true
		}
	}
	// Same rationale as removeWithResyncFallback: the DB rows already flipped
	// to expired, so a failed Remove otherwise leaves those devices online
	// until the next periodic reconcile. One resync converges everything.
	if removeFailed {
		if rerr := s.resyncLocked(ctx); rerr != nil {
			log.Printf("ERROR: firewall resync after failed expiry removes: %v (expired MACs may stay online until next resync)", rerr)
		}
	}
	if len(expired) > 0 {
		log.Printf("expired %d MACs", len(expired))
	}
	return len(expired), nil
}
