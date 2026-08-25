package scheduler

import (
	"context"
	"log"
	"time"
)

// Expirer is the single-method interface Run needs from MACService.
// Defining it here (rather than importing *service.MACService) lets tests
// pass a closure or fake without dragging in the whole service+db+firewall
// graph just to exercise the scheduler tick.
type Expirer interface {
	ExpireDue(ctx context.Context) (int, error)
}

// Resyncer is the optional companion interface: when the Expirer also
// implements it (MACService does), each tick additionally reconciles the
// firewall set against the DB. This self-heals drift from transient
// firewall failures (e.g. an `nft` invocation that failed during a paid
// grant) without waiting for a restart or a manual /admin/resync.
type Resyncer interface {
	Resync(ctx context.Context) error
}

// Run blocks until ctx is canceled. Calls e.ExpireDue() once immediately
// (so a freshly-restarted server processes any backlog) and then on each
// tick of `interval`. Errors are logged and the loop continues — a transient
// DB hiccup shouldn't stop the cron forever.
func Run(ctx context.Context, e Expirer, interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}
	if _, err := e.ExpireDue(ctx); err != nil {
		log.Printf("scheduler: initial expire: %v", err)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := e.ExpireDue(ctx); err != nil {
				log.Printf("scheduler: expire: %v", err)
			}
			if rs, ok := e.(Resyncer); ok {
				if err := rs.Resync(ctx); err != nil {
					log.Printf("scheduler: resync: %v", err)
				}
			}
		}
	}
}
