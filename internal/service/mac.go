package service

import (
	"context"
	"fmt"
	"log"
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
}

func New(d *db.DB, fw firewall.API) *MACService {
	return &MACService{DB: d, FW: fw}
}

// GrantFromOrder adds days to MAC's expiry then puts it into the firewall set.
// If the order is linked to a user, that user becomes the MAC's owner.
func (s *MACService) GrantFromOrder(ctx context.Context, o *models.Order) error {
	label := fmt.Sprintf("paid-%s", o.Plan)
	m, err := s.DB.UpsertMAC(ctx, o.Mac, label, o.Days, o.UserID)
	if err != nil {
		return fmt.Errorf("upsert mac: %w", err)
	}
	if err := s.FW.Add(ctx, m.Mac); err != nil {
		log.Printf("warn: firewall add %s: %v", m.Mac, err)
		return err
	}
	log.Printf("granted %s for %d days (until %s) from order %s", m.Mac, o.Days, m.ExpiresAt.Format("2006-01-02"), o.OrderNo)
	return nil
}

// Extend is the admin-manual version of GrantFromOrder.
func (s *MACService) Extend(ctx context.Context, mac, label string, days int, userID *int64) (*models.MAC, error) {
	m, err := s.DB.UpsertMAC(ctx, mac, label, days, userID)
	if err != nil {
		return nil, err
	}
	if err := s.FW.Add(ctx, m.Mac); err != nil {
		return nil, err
	}
	return m, nil
}

// RedeemVoucherGrant consumes a voucher and grants its days to the MAC as
// ONE DB transaction, then adds the MAC to the firewall best-effort.
//
// The firewall add deliberately does NOT fail the redemption: the DB is
// the source of truth and the hourly scheduler reconcile (plus manual
// /admin/resync) self-heals set drift. Failing here would burn the
// customer's voucher over a transient nft/ipset hiccup — the one outcome
// this method exists to prevent. A failed add is returned via fwErr so
// the caller can audit it without telling the customer their code is gone.
func (s *MACService) RedeemVoucherGrant(ctx context.Context, code, mac string, userID *int64) (v *models.Voucher, m *models.MAC, fwErr error, err error) {
	v, m, err = s.DB.RedeemVoucherGrant(ctx, code, mac, userID)
	if err != nil {
		return nil, nil, nil, err
	}
	if aerr := s.FW.Add(ctx, m.Mac); aerr != nil {
		log.Printf("warn: firewall add %s after voucher redeem: %v (reconcile will heal)", m.Mac, aerr)
		fwErr = aerr
	}
	return v, m, fwErr, nil
}

// Revoke marks blocked + drops from firewall set.
func (s *MACService) Revoke(ctx context.Context, mac string) error {
	if err := s.DB.SetMACStatus(ctx, mac, models.MACBlocked); err != nil {
		return err
	}
	return s.FW.Remove(ctx, mac)
}

// Delete removes from DB + firewall.
func (s *MACService) Delete(ctx context.Context, mac string) error {
	if err := s.DB.DeleteMAC(ctx, mac); err != nil {
		return err
	}
	return s.FW.Remove(ctx, mac)
}

// Replace transfers a user's remaining time from oldMac to newMac.
// Both DB row and firewall set are updated atomically.
func (s *MACService) Replace(ctx context.Context, userID int64, oldMac, newMac, label string) (*models.MAC, error) {
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
	now := time.Now()
	macs, err := s.DB.ListActiveMACs(ctx)
	if err != nil {
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

// ExpireDue marks expired DB rows and yanks them from firewall.
func (s *MACService) ExpireDue(ctx context.Context) (int, error) {
	expired, err := s.DB.ExpireDueMACs(ctx)
	if err != nil {
		return 0, err
	}
	for _, m := range expired {
		if err := s.FW.Remove(ctx, m); err != nil {
			log.Printf("warn: firewall remove %s: %v", m, err)
		}
	}
	if len(expired) > 0 {
		log.Printf("expired %d MACs", len(expired))
	}
	return len(expired), nil
}
