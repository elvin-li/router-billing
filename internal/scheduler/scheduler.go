package scheduler

import (
	"context"
	"log"
	"time"

	"router-billing/internal/service"
)

// Run blocks until ctx is canceled. It periodically expires MACs.
func Run(ctx context.Context, svc *service.MACService, interval time.Duration) {
	if interval <= 0 {
		interval = time.Hour
	}
	// Run once immediately so startup catches any backlog.
	if _, err := svc.ExpireDue(ctx); err != nil {
		log.Printf("scheduler: initial expire: %v", err)
	}
	t := time.NewTicker(interval)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			if _, err := svc.ExpireDue(ctx); err != nil {
				log.Printf("scheduler: expire: %v", err)
			}
		}
	}
}
