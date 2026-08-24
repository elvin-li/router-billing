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
// DB hiccup shouldn't stop the cron forever. Panics inside a pass are
// recovered for the same reason: this goroutine is what keeps the firewall
// honest, and an unrecovered panic here would take down the whole
// router-billing process (billing UI, payment webhooks, everything) over
// one bad tick.
func Run(ctx context.Context, e Expirer, interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}
	expireOnce(ctx, e, "initial ")
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			expireOnce(ctx, e, "")
			if rs, ok := e.(Resyncer); ok {
				resyncOnce(ctx, rs)
			}
		}
	}
}

// expireOnce runs one expiry pass, converting a panic into a log line so
// the cron survives it.
func expireOnce(ctx context.Context, e Expirer, kind string) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("scheduler: %sexpire panicked (recovered, cron continues): %v", kind, r)
		}
	}()
	if _, err := e.ExpireDue(ctx); err != nil {
		log.Printf("scheduler: %sexpire: %v", kind, err)
	}
}

// resyncOnce runs one firewall reconcile pass with the same panic
// containment as expireOnce. The initial boot pass is expire-only —
// main.go already resyncs at startup.
func resyncOnce(ctx context.Context, rs Resyncer) {
	defer func() {
		if r := recover(); r != nil {
			log.Printf("scheduler: resync panicked (recovered, cron continues): %v", r)
		}
	}()
	if err := rs.Resync(ctx); err != nil {
		log.Printf("scheduler: resync: %v", err)
	}
}
