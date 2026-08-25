package server

import (
	"context"
	"testing"
	"time"
)

// purgeLoop must run one housekeeping pass at boot. Routers in the field
// are commonly power-cycled daily; a janitor that only fires after 2h of
// continuous uptime never runs on such boxes and lets expired sessions /
// log tables grow without bound.
func TestPurgeLoopRunsInitialPassAtBoot(t *testing.T) {
	app := setupTestApp(t)
	ctx := context.Background()

	if _, err := app.DB.Exec(ctx,
		`INSERT INTO sessions (token, kind, subject, expires_at)
		 VALUES ('purge-boot-tok', 'admin', 'x', datetime('now','-1 hour'))`); err != nil {
		t.Fatal(err)
	}

	loopCtx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		app.purgeLoop(loopCtx)
		close(done)
	}()

	// The initial pass runs before the first 2h tick — the expired session
	// should disappear promptly, without advancing any clock. Probe row
	// existence via a no-op UPDATE's RowsAffected (DB has no raw query
	// helper, and GetSession filters expired rows out).
	deadline := time.After(2 * time.Second)
	for {
		res, err := app.DB.Exec(ctx,
			`UPDATE sessions SET subject = subject WHERE token='purge-boot-tok'`)
		if err != nil {
			t.Fatal(err)
		}
		n, _ := res.RowsAffected()
		if n == 0 {
			break
		}
		select {
		case <-deadline:
			t.Fatal("expired session still present — purgeLoop did not run an initial pass at boot")
		default:
			time.Sleep(10 * time.Millisecond)
		}
	}

	cancel()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("purgeLoop did not exit on ctx cancel")
	}
}
