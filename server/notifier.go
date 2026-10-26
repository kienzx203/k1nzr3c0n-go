package server

import (
	"context"
	"encoding/json"
	"fmt"
	"log"
	"sync"
	"time"

	"github.com/Autumn-27/artex/db"
	"github.com/Autumn-27/artex/notify"
)

// Global setting keys (stored in the settings key-value table; no dedicated table needed).
const (
	// settingNotifyEnabled is the master push switch. Default on: it exists as a
	// one-click kill switch during maintenance, not as the feature's enable
	// condition — the real enable condition is "is any channel configured".
	settingNotifyEnabled = "notify_enabled"
	// settingNotifyPublicBaseURL is the externally reachable address used to build
	// a backlink to the vulnerability detail page (e.g. https://artex.example.com).
	// Leave it empty and the message carries no backlink button.
	// The project has no reusable external-address config, so this adds one.
	settingNotifyPublicBaseURL = "notify_public_base_url"
	// settingNotifyDigestMinutes is the digest-mode interval (minutes).
	settingNotifyDigestMinutes = "notify_digest_interval_min"
)

const (
	// notifyTick is the delivery engine's polling interval. 3 seconds is the upper
	// bound on this engine's latency, and the main source of delay between
	// "vulnerability persisted" and "message arriving in the IM".
	notifyTick = 3 * time.Second
	// notifyLease is the lease duration when claiming a delivery. It must be
	// significantly larger than the worst-case time of a single delivery (the
	// notify package's HTTP client times out after 15 seconds), otherwise the
	// same row gets delivered by two dispatchers at once.
	notifyLease = 3 * time.Minute
	// notifyFanOutPerTick caps the number of events dispatched per tick, so that
	// first enabling a channel does not expand the entire historical backlog into
	// delivery tasks all at once.
	notifyFanOutPerTick = 200
	// notifyDefaultDigestMinutes is the default digest interval.
	notifyDefaultDigestMinutes = 30
	// notifyUnlimitedBurstPerTick is the per-tick delivery cap for a channel with
	// no rate limit set. Its purpose is to stop "one channel configured as
	// unlimited + a scan turning up thousands of vulnerabilities" from stalling a
	// single loop iteration for a long time.
	notifyUnlimitedBurstPerTick = 50
	// notifyMaxSendsPerChannelPerTick is the max number of deliveries per channel
	// per tick.
	//
	// This cap is derived backwards from the **lease duration**: claiming stamps
	// the row with a lease (notifyLease = 3 minutes), and if a tick delivers
	// serially enough rows that the worst-case time exceeds the lease, the lease on
	// the later rows expires before they are even sent.
	// Within a single process this does not matter (Run is a single goroutine
	// running serially, and ticks do not re-enter), but with **two processes
	// sharing one database** the peer re-claims lease-expired rows and sends them
	// again, double-incrementing attempts and judging them failed while the
	// original process is still delivering.
	//
	// Value: 3-minute lease / 30-second per-send timeout = 6 **exactly fills the
	// lease** with zero margin, so it cannot be used; 5 keeps the worst case at
	// 150 seconds, leaving 30 seconds of margin. This relationship is pinned by
	// TestNotifyTickBudgetFitsWithinLease — changing any one of notifyLease,
	// notifySendTimeout, or this value will make that assertion fail.
	notifyMaxSendsPerChannelPerTick = 5
	// notifySendTimeout is the timeout for a single delivery. It also determines
	// the value of the previous constant; their product must not exceed
	// notifyLease, see TestNotifyTickBudgetFitsWithinLease.
	notifySendTimeout = 30 * time.Second
)

// notifyBackoff is the retry-on-failure backoff sequence, indexed by attempts
// already made. The 3 chances (including the first) correspond to
// db.MaxNotifyAttempts; the two must be changed together.
var notifyBackoff = []time.Duration{
	time.Second,
	5 * time.Second,
	30 * time.Second,
}

// Notifier is the delivery engine for vulnerability push notifications.
//
// It runs alongside Scheduler as an independent goroutine (see server.New). It
// deliberately does not reuse Scheduler's tick: the push latency requirement
// (3 seconds) differs from the triggers' business cadence, and the two
// failures are independent — a stuck push must not affect agent triggers.
type Notifier struct {
	s  *Server
	pg *db.DB

	// mu guards buckets. Channels are few and contention is low, so one mutex is
	// enough; it is not worth introducing a finer-grained structure for it.
	mu      sync.Mutex
	buckets map[int64]*notifyBucket
}

// notifyBucket is the token bucket for a single channel.
//
// A token bucket is used rather than a "count per minute then reset" sliding
// window because the latter has nasty boundary effects: sending 20 at the end
// of a window and another 20 the next instant looks to the platform like 40 in
// one second and gets rate-limited; a token bucket refills at a constant rate
// and naturally avoids such bursts.
type notifyBucket struct {
	tokens   float64
	lastFill time.Time
}

func newNotifier(s *Server) *Notifier {
	return &Notifier{s: s, pg: s.m.pg, buckets: map[int64]*notifyBucket{}}
}

// Run loops until ctx ends. Started once by server.New.
func (n *Notifier) Run(ctx context.Context) {
	if n.pg == nil {
		return
	}
	t := time.NewTicker(notifyTick)
	defer t.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-t.C:
			n.step(ctx)
		}
	}
}

// step runs one round: first dispatch new events, then deliver the due tasks.
//
// A failure in any step only logs and does not break the loop — a failure in
// the notification system must never escalate into a process-level problem.
// Each tick is independent, and the next round retries naturally.
func (n *Notifier) step(ctx context.Context) {
	if !n.enabled() {
		return
	}
	if _, _, err := n.pg.FanOutPendingEvents(ctx, notifyFanOutPerTick); err != nil {
		log.Printf("[notify] dispatch events failed: %v", err)
		return
	}
	channels, err := n.pg.ListNotificationChannels(ctx)
	if err != nil {
		log.Printf("[notify] read channels failed: %v", err)
		return
	}
	baseURL := n.publicBaseURL()
	for _, ch := range channels {
		if !ch.IsEnabled() {
			continue
		}
		// The token bucket's unit of measure is **number of messages**
		// (equivalent to number of HTTP requests), not number of
		// vulnerabilities. In realtime mode the two are the same (one
		// vulnerability, one message); in digest mode a whole batch of
		// vulnerabilities is combined into one message, so it consumes only one
		// token.
		//
		// Both modes ask the token bucket first and then claim against the
		// quota — the order cannot be reversed, otherwise a delivery blocked by
		// the rate limit has already consumed a retry attempt.
		now := time.Now()
		if ch.Mode == db.NotifyModeDigest {
			tokens, claimLimit := digestTickPlan()
			if n.takeTokens(ch.ID, ch.RatePerMin, tokens, now) <= 0 {
				continue
			}
			n.stepDigest(ctx, ch, claimLimit, baseURL)
			continue
		}
		allow := n.takeTokens(ch.ID, ch.RatePerMin, notifyMaxSendsPerChannelPerTick, now)
		if allow <= 0 {
			continue
		}
		n.stepRealtime(ctx, ch, allow, baseURL)
	}
}

// digestTickPlan returns this round's token consumption and the upper bound on
// batch size for a digest channel.
//
// The two return values are **two different dimensions**, which is exactly why
// this is its own function:
//
//   - tokens is the number of messages. A batch of vulnerabilities is combined
//     into one message and sent as one HTTP request, so it is always 1.
//     rate_per_min therefore still applies to digest (at most this many digest
//     messages per minute).
//   - claimLimit is how many vulnerabilities this batch holds at most. It is
//     bounded only by the in-memory cap and is unrelated to the request budget.
//
// To make rate_per_min apply to digest, the per-tick request budget
// (notifyMaxSendsPerChannelPerTick, itself derived backwards from the lease)
// used to be passed straight down as the batch size. The result was that a
// channel with rate_per_min=20 refills only 1 token within the 3-second tick,
// so each digest message holds just 1 vulnerability — digest degenerated into
// "realtime push with digest wording", and readers received a stream of "1 new
// vulnerability in the last 30 minutes", while db.MaxDigestBatchSize was never
// reachable.
//
// This symptom is hard to spot in end-to-end tests (the existing cases all pass
// a large enough limit to stepDigest by hand, bypassing step's quota math), so
// the decision is pinned here directly by
// TestDigestTickPlanDecouplesBatchSizeFromSendBudget.
func digestTickPlan() (tokens, claimLimit int) {
	return 1, db.MaxDigestBatchSize
}

// stepRealtime claims and delivers a channel's realtime tasks, one vulnerability
// per message.
func (n *Notifier) stepRealtime(ctx context.Context, ch *db.NotificationChannel, allow int, baseURL string) {
	deliveries, err := n.pg.ClaimRealtimeDeliveries(ctx, ch.ID, allow, notifyLease)
	if err != nil {
		log.Printf("[notify] claim realtime deliveries failed channel=%d: %v", ch.ID, err)
		return
	}
	if len(deliveries) == 0 {
		return
	}
	channel, cfg, ok := n.adapt(ch)
	if !ok {
		_ = n.pg.FailDeliveries(ctx, deliveryIDs(deliveries), fmt.Sprintf("channel type %q not registered", ch.Kind))
		return
	}
	for _, dl := range deliveries {
		msg, err := n.renderSingle(ctx, dl, baseURL)
		if err != nil {
			// A render failure is a local data problem; retrying will not help.
			_ = n.pg.FailDeliveries(ctx, []int64{dl.ID}, err.Error())
			continue
		}
		n.send(ctx, channel, cfg, msg, []*db.NotificationDelivery{dl})
	}
}

// stepDigest aggregates a channel's pending deliveries into one message and
// sends it when the batch is due.
func (n *Notifier) stepDigest(ctx context.Context, ch *db.NotificationChannel, allow int, baseURL string) {
	window := n.digestInterval()
	due, err := n.pg.DigestBatchDue(ctx, ch.ID, window)
	if err != nil {
		log.Printf("[notify] determine digest batch failed channel=%d: %v", ch.ID, err)
		return
	}
	if !due {
		return
	}
	deliveries, err := n.pg.ClaimDigestBatch(ctx, ch.ID, allow, notifyLease)
	if err != nil {
		log.Printf("[notify] claim digest batch failed channel=%d: %v", ch.ID, err)
		return
	}
	if len(deliveries) == 0 {
		return
	}
	channel, cfg, ok := n.adapt(ch)
	if !ok {
		_ = n.pg.FailDeliveries(ctx, deliveryIDs(deliveries), fmt.Sprintf("channel type %q not registered", ch.Kind))
		return
	}
	msg, included, err := n.renderBatch(ctx, deliveries, baseURL, int(window.Minutes()))
	if err != nil {
		_ = n.pg.FailDeliveries(ctx, deliveryIDs(deliveries), err.Error())
		return
	}
	// Deliveries whose snapshot is broken and did not make it into the message
	// must be explicitly failed. Otherwise they stay outside included — in
	// neither the message nor the failure list — and on a successful send their
	// status gets missed by the later batch marking, stuck forever in sending
	// until the lease expires and they are claimed over and over.
	if skipped := excludeDeliveries(deliveries, included); len(skipped) > 0 {
		reason := "event snapshot could not be parsed; this vulnerability cannot be rendered into a message"
		if fErr := n.pg.FailDeliveries(ctx, deliveryIDs(skipped), reason); fErr != nil {
			log.Printf("[notify] mark bad-snapshot deliveries failed channel=%s ids=%v: %v", ch.Kind, deliveryIDs(skipped), fErr)
		}
		log.Printf("[notify] skipped %d deliveries with unparseable snapshots channel=%d", len(skipped), ch.ID)
	}
	// Hand send only the ones that made it into the message: included[i]
	// corresponds strictly to msg.Items[i], and send relies on this
	// correspondence to apply "the channel reported it accepted the first K" to
	// the right delivery rows.
	n.send(ctx, channel, cfg, msg, included)
}

// send delivers and transitions status according to the result.
//
// One batch of deliveries (possibly dozens in digest mode) shares a single send
// result: either delivered, or the whole batch retries. It does no per-item
// retry — a digest message is one message, and resending part of it would
// scramble the batch's semantics.
//
// The one exception is **segmentation caused by a channel's length cap**: the
// channel reports it actually accepted only the first K, so from the (K+1)th on
// they must be held for the next batch rather than marked successful along with
// the rest. Otherwise the truncated vulnerabilities are in neither the message
// nor the failure list and vanish entirely.
func (n *Notifier) send(ctx context.Context, channel notify.Channel, cfg map[string]any, msg notify.Message, deliveries []*db.NotificationDelivery) {
	// Cap a single delivery so a stuck channel does not drag down all remaining
	// channels this round.
	sendCtx, cancel := context.WithTimeout(ctx, notifySendTimeout)
	defer cancel()
	delivered, err := channel.Send(sendCtx, cfg, msg)
	if err == nil && delivered > 0 {
		if delivered > len(deliveries) {
			// The channel cannot report more delivered than were handed to it;
			// if it really happens the render layer miscounted. Treating it as
			// all-delivered and recording the problem beats scrambling the
			// records.
			log.Printf("[notify] channel reported delivered count %d exceeds delivery count %d channel=%s, treating as all delivered",
				delivered, len(deliveries), channel.Kind())
			delivered = len(deliveries)
		}
		sent, rest := deliveries[:delivered], deliveries[delivered:]
		if err := n.pg.MarkDeliveriesSent(ctx, deliveryIDs(sent)); err != nil {
			log.Printf("[notify] mark delivered failed channel=%s ids=%v: %v", channel.Kind(), deliveryIDs(sent), err)
		}
		if len(rest) > 0 {
			// This message hit the channel's length cap: the rest go straight
			// back to the queue and continue on the next tick. Use
			// DeferDeliveries rather than RescheduleDeliveries — this is not a
			// failure and should not consume the retry budget (claiming already
			// optimistically +1'd, and that is decremented back there).
			if err := n.pg.DeferDeliveries(ctx, deliveryIDs(rest),
				fmt.Sprintf("this message hit the channel's length cap, only the first %d were delivered, the rest are held for the next batch", delivered)); err != nil {
				log.Printf("[notify] queue continuation segment failed channel=%s ids=%v: %v", channel.Kind(), deliveryIDs(rest), err)
			}
		}
		return
	}
	if err == nil {
		// The channel neither reported an error nor said how many were
		// delivered. Treat it as a failure (with backoff) so this delivery is
		// not claimed over and over yet never markable.
		err = fmt.Errorf("channel did not report a delivered count (delivered=%d)", delivered)
	}

	// Failure handling is decided **per item** rather than from the batch's max
	// attempt count.
	//
	// It used to be `if maxAttempts(deliveries) >= MaxNotifyAttempts` judging the
	// whole batch dead, but attempt counts within a batch differ: an old delivery
	// already retried twice (attempts=2) would drag brand-new deliveries
	// (attempts=1) in the same batch into failed — a new vulnerability lost
	// permanently without a single retry used, exactly the opposite of the intent
	// "do not let old rows drag new rows under".
	permanent := notify.IsPermanent(err)
	var failIDs, exhaustedIDs []int64
	byDelay := map[time.Duration][]int64{}
	for _, dl := range deliveries {
		switch {
		case permanent:
			failIDs = append(failIDs, dl.ID)
		case dl.Attempts >= db.MaxNotifyAttempts:
			exhaustedIDs = append(exhaustedIDs, dl.ID)
		default:
			delay := notifyBackoff[min(dl.Attempts, len(notifyBackoff)-1)]
			byDelay[delay] = append(byDelay[delay], dl.ID)
		}
	}

	if len(failIDs) > 0 {
		if fErr := n.pg.FailDeliveries(ctx, failIDs, err.Error()); fErr != nil {
			log.Printf("[notify] mark failed status errored channel=%s ids=%v: %v", channel.Kind(), failIDs, fErr)
		}
	}
	if len(exhaustedIDs) > 0 {
		reason := fmt.Sprintf("still failing after %d retries: %s", db.MaxNotifyAttempts, err)
		if fErr := n.pg.FailDeliveries(ctx, exhaustedIDs, reason); fErr != nil {
			log.Printf("[notify] mark failed status errored channel=%s ids=%v: %v", channel.Kind(), exhaustedIDs, fErr)
		}
	}
	// Regroup and reschedule by delay: with only 3 backoff tiers the number of
	// groups is naturally small, so there is no need to issue one UPDATE per item
	// (that would make a 500-item batch do 500 round trips).
	for delay, group := range byDelay {
		if rErr := n.pg.RescheduleDeliveries(ctx, group, delay, err.Error()); rErr != nil {
			log.Printf("[notify] reschedule deliveries failed channel=%s ids=%v: %v", channel.Kind(), group, rErr)
		}
	}
	if len(failIDs)+len(exhaustedIDs) > 0 {
		log.Printf("[notify] delivery failed channel=%d kind=%s permanent=%d retries-exhausted=%d pending-retry=%d: %s",
			deliveries[0].ChannelID, channel.Kind(), len(failIDs), len(exhaustedIDs), len(byDelay), err)
	}
}

// excludeDeliveries returns the entries of all that are not in keep (compared by
// pointer identity). Used to find the deliveries that "did not make it into the
// message" — they must be handled explicitly and cannot be left in limbo.
func excludeDeliveries(all, keep []*db.NotificationDelivery) []*db.NotificationDelivery {
	inKeep := make(map[*db.NotificationDelivery]bool, len(keep))
	for _, dl := range keep {
		inKeep[dl] = true
	}
	var out []*db.NotificationDelivery
	for _, dl := range all {
		if !inKeep[dl] {
			out = append(out, dl)
		}
	}
	return out
}

// adapt gets the channel implementation and parses its config.
// ok=false means the type is not registered and the delivery should be failed
// directly rather than retried forever.
func (n *Notifier) adapt(ch *db.NotificationChannel) (notify.Channel, map[string]any, bool) {
	channel, ok := notify.Get(ch.Kind)
	if !ok {
		return nil, nil, false
	}
	var cfg map[string]any
	if len(ch.Config) > 0 {
		// Give an empty map on a config parse failure: the channel's own
		// Validate reports "which field is missing", and that error guides the
		// user to a fix better than a JSON parse error.
		_ = json.Unmarshal(ch.Config, &cfg)
	}
	if cfg == nil {
		cfg = map[string]any{}
	}
	return channel, cfg, true
}

// renderSingle renders a single-vulnerability message.
func (n *Notifier) renderSingle(ctx context.Context, dl *db.NotificationDelivery, baseURL string) (notify.Message, error) {
	snap, err := parseSnapshot(dl)
	if err != nil {
		return notify.Message{}, err
	}
	item, err := n.itemFor(ctx, snap, baseURL)
	if err != nil {
		return notify.Message{}, err
	}
	return notify.Message{Items: []notify.Item{item}, HomeURL: baseURL}, nil
}

// renderBatch renders a digest message. It parses snapshots one by one — if a
// single one is broken it skips just that one, rather than letting it sink the
// whole digest.
//
// The return value included corresponds **strictly one-to-one** with msg.Items
// (the i-th delivery ↔ the i-th item). This correspondence is a hard
// requirement: the caller uses "the channel reported it accepted the first K"
// to decide which first K deliveries are marked delivered. If a bad snapshot is
// skipped here but the skipped delivery is not removed from included, the
// indices shift — an item that should have failed gets marked delivered, and a
// good item gets wrongly judged undelivered.
// The broken ones are explicitly failed by the caller, see stepDigest.
func (n *Notifier) renderBatch(ctx context.Context, deliveries []*db.NotificationDelivery, baseURL string, windowMinutes int) (notify.Message, []*db.NotificationDelivery, error) {
	items := make([]notify.Item, 0, len(deliveries))
	included := make([]*db.NotificationDelivery, 0, len(deliveries))
	for _, dl := range deliveries {
		snap, err := parseSnapshot(dl)
		if err != nil {
			// A bad snapshot goes into neither the message nor included — its
			// handling is the caller's responsibility (explicitly marked
			// failed, not slipped through hidden among the "delivered").
			log.Printf("[notify] skipped an unparseable snapshot in digest batch delivery=%d: %v", dl.ID, err)
			continue
		}
		item, err := n.itemFor(ctx, snap, baseURL)
		if err != nil {
			return notify.Message{}, nil, err
		}
		items = append(items, item)
		included = append(included, dl)
	}
	if len(items) == 0 {
		return notify.Message{}, nil, fmt.Errorf("all %d deliveries in the digest batch were unparseable", len(deliveries))
	}
	return notify.Message{
		Items:         items,
		Batch:         true,
		WindowMinutes: windowMinutes,
		HomeURL:       baseURL,
	}, included, nil
}

// itemFor renders an event snapshot into a pushable item, resolving the asset
// names and detail backlink along the way.
func (n *Notifier) itemFor(ctx context.Context, snap notify.Snapshot, baseURL string) (notify.Item, error) {
	assets, err := n.pg.NotificationAssetNames(ctx, snap.AssetIDs)
	if err != nil {
		// A failure to resolve asset names should not block the push: not
		// reading a name is far lighter than not receiving a notification —
		// the message just has one fewer asset line.
		log.Printf("[notify] resolve asset names failed finding=%d: %v", snap.FindingID, err)
	}
	item := notify.Item{
		FindingID:  snap.FindingID,
		Name:       snap.Name,
		VulnClass:  snap.VulnClass,
		Severity:   snap.Severity,
		Summary:    snap.Summary,
		Assets:     assets,
		FromStatus: snap.FromStatus,
		ToStatus:   snap.ToStatus,
	}
	if baseURL != "" {
		// For the detail-page route see
		// web/src/app/(main)/function/findings/detail/page.tsx, which reads the
		// vulnerability id from the query parameter id.
		item.DetailURL = fmt.Sprintf("%s/function/findings/detail?id=%d", baseURL, snap.FindingID)
	}
	return item, nil
}

// takeTokens takes **at most want** tokens from the channel's token bucket and
// returns the number actually taken.
//
// One token = one message (one HTTP request). In realtime mode the caller passes
// however many it wants; in digest mode a whole batch of vulnerabilities sends
// as one message, so it passes 1.
//
// The bucket capacity is the channel's per-minute cap, refilled at a constant
// rate. ratePerMin<=0 means unlimited and returns a finite but large enough
// value, to stop a single loop iteration from being dragged down by an
// unbounded backlog.
//
// The want cap is required: without it one could only drain the whole bucket,
// yet the caller has its own per-tick cap, so the extra tokens are both unusable
// and vanish out of thin air before the next refill — the accumulated burst
// capacity is never reachable, and even "no pending delivery this round" would
// still be charged.
func (n *Notifier) takeTokens(channelID int64, ratePerMin, want int, now time.Time) int {
	if want <= 0 {
		return 0
	}
	if ratePerMin <= 0 {
		return min(want, notifyUnlimitedBurstPerTick)
	}
	n.mu.Lock()
	defer n.mu.Unlock()
	b := n.buckets[channelID]
	if b == nil {
		b = &notifyBucket{tokens: float64(ratePerMin), lastFill: now}
		n.buckets[channelID] = b
	}
	// Refill by real elapsed time, at a rate of ratePerMin/60 per second.
	if elapsed := now.Sub(b.lastFill).Seconds(); elapsed > 0 {
		b.tokens = minF(float64(ratePerMin), b.tokens+elapsed*float64(ratePerMin)/60)
		b.lastFill = now
	}
	// Add a tiny epsilon before truncating: the token count is accumulated in
	// floating point, so refilling in two halves of 0.5 + 0.5 may give
	// 0.9999999999, and a plain int() would truncate it to 0 — a bucket full in
	// math yet yielding no token. 1e-9 is far less than one token and will not
	// let a real shortfall slip by.
	take := min(int(b.tokens+1e-9), want)
	if take <= 0 {
		return 0
	}
	b.tokens -= float64(take)
	return take
}

// enabled reads the master switch.
func (n *Notifier) enabled() bool {
	return n.pg.GetBool(settingNotifyEnabled, true)
}

// publicBaseURL returns the external address used for backlinks, with the
// trailing slash stripped.
func (n *Notifier) publicBaseURL() string {
	v, ok, err := n.pg.GetSetting(settingNotifyPublicBaseURL)
	if err != nil || !ok {
		return ""
	}
	return trimTrailingSlash(v)
}

// digestInterval returns the digest interval, falling back to the default when
// it is invalid or not configured.
func (n *Notifier) digestInterval() time.Duration {
	v, ok, err := n.pg.GetSetting(settingNotifyDigestMinutes)
	if err != nil || !ok {
		return time.Duration(notifyDefaultDigestMinutes) * time.Minute
	}
	m := 0
	if _, err := fmt.Sscanf(v, "%d", &m); err != nil || m <= 0 {
		return time.Duration(notifyDefaultDigestMinutes) * time.Minute
	}
	return time.Duration(m) * time.Minute
}

// parseSnapshot parses the snapshot of a delivery's corresponding event.
func parseSnapshot(dl *db.NotificationDelivery) (notify.Snapshot, error) {
	var snap notify.Snapshot
	if len(dl.Snapshot) == 0 {
		return snap, fmt.Errorf("event snapshot for delivery %d is empty", dl.ID)
	}
	if err := json.Unmarshal(dl.Snapshot, &snap); err != nil {
		return snap, fmt.Errorf("parse event snapshot for delivery %d failed: %w", dl.ID, err)
	}
	if snap.Kind == "" {
		// The event type follows the event row; the copy in the snapshot may
		// have been written by an older version.
		snap.Kind = dl.EventKind
	}
	return snap, nil
}

func deliveryIDs(deliveries []*db.NotificationDelivery) []int64 {
	out := make([]int64, 0, len(deliveries))
	for _, dl := range deliveries {
		out = append(out, dl.ID)
	}
	return out
}

func trimTrailingSlash(s string) string {
	for len(s) > 0 && s[len(s)-1] == '/' {
		s = s[:len(s)-1]
	}
	return s
}

func minF(a, b float64) float64 {
	if a < b {
		return a
	}
	return b
}
