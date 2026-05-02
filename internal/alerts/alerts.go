package alerts

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"os"
	"strings"
	"sync"
	"time"

	"github.com/nggurbanov/remnaguard/internal/config"
)

type Event struct {
	Name      string
	Route     string
	TokenID   string
	Reason    string
	Status    int
	CreatedAt time.Time
}

type Manager struct {
	mu      sync.Mutex
	cfg     config.AlertsConfig
	client  *http.Client
	queue   chan Event
	buckets map[string]*bucket
	stop    chan struct{}
	done    chan struct{}
}

type bucket struct {
	event    Event
	first    time.Time
	last     time.Time
	count    int
	lastSent time.Time
}

func NewManager(cfg config.AlertsConfig) *Manager {
	queueSize := cfg.Telegram.QueueSize
	if queueSize == 0 {
		queueSize = 100
	}
	m := &Manager{
		cfg:     cfg,
		client:  &http.Client{},
		queue:   make(chan Event, queueSize),
		buckets: make(map[string]*bucket),
		stop:    make(chan struct{}),
		done:    make(chan struct{}),
	}
	go m.run()
	return m
}

func (m *Manager) Update(cfg config.AlertsConfig) {
	m.mu.Lock()
	defer m.mu.Unlock()
	m.cfg = cfg
}

func (m *Manager) Close() {
	close(m.stop)
	<-m.done
}

func (m *Manager) Notify(event Event) {
	m.mu.Lock()
	enabled := m.cfg.Enabled && m.cfg.Telegram.Enabled && event.Name == "request_denied"
	m.mu.Unlock()
	if !enabled {
		return
	}
	if event.CreatedAt.IsZero() {
		event.CreatedAt = time.Now().UTC()
	}
	select {
	case m.queue <- event:
	default:
		log.Printf("remnaguard alerts: queue full; dropping alert event route=%q reason=%q", event.Route, event.Reason)
	}
}

func (m *Manager) run() {
	ticker := time.NewTicker(10 * time.Second)
	defer func() {
		ticker.Stop()
		close(m.done)
	}()
	for {
		select {
		case ev := <-m.queue:
			m.record(ev)
		case <-ticker.C:
			m.flushDue(time.Now().UTC())
		case <-m.stop:
			m.flushAll()
			return
		}
	}
}

func (m *Manager) record(ev Event) {
	now := ev.CreatedAt.UTC()
	key := alertKey(ev)
	var send *bucket

	m.mu.Lock()
	b := m.buckets[key]
	if b == nil {
		b = &bucket{event: ev, first: now, last: now}
		m.buckets[key] = b
	}
	b.event = ev
	b.last = now
	b.count++
	cooldown := m.cooldownLocked()
	if b.lastSent.IsZero() || now.Sub(b.lastSent) >= cooldown {
		send = cloneBucket(b)
		b.count = 0
		b.first = now
		b.lastSent = now
	}
	m.mu.Unlock()

	if send != nil {
		m.send(*send)
	}
}

func (m *Manager) flushDue(now time.Time) {
	var sends []bucket
	m.mu.Lock()
	cooldown := m.cooldownLocked()
	for _, b := range m.buckets {
		if b.count == 0 {
			continue
		}
		if !b.lastSent.IsZero() && now.Sub(b.lastSent) < cooldown {
			continue
		}
		sends = append(sends, *cloneBucket(b))
		b.count = 0
		b.first = now
		b.lastSent = now
	}
	m.mu.Unlock()
	for _, b := range sends {
		m.send(b)
	}
}

func (m *Manager) flushAll() {
	var sends []bucket
	m.mu.Lock()
	for _, b := range m.buckets {
		if b.count > 0 {
			sends = append(sends, *cloneBucket(b))
		}
	}
	m.mu.Unlock()
	for _, b := range sends {
		m.send(b)
	}
}

func (m *Manager) cooldownLocked() time.Duration {
	if m.cfg.Telegram.Cooldown > 0 {
		return m.cfg.Telegram.Cooldown
	}
	return 5 * time.Minute
}

func cloneBucket(b *bucket) *bucket {
	cp := *b
	return &cp
}

func alertKey(ev Event) string {
	return strings.Join([]string{emptyDash(ev.TokenID), emptyDash(ev.Route), emptyDash(ev.Reason), fmt.Sprint(ev.Status)}, "|")
}

func (m *Manager) send(b bucket) {
	m.mu.Lock()
	cfg := m.cfg
	m.mu.Unlock()
	if !cfg.Enabled || !cfg.Telegram.Enabled {
		return
	}
	token := strings.TrimSpace(os.Getenv(cfg.Telegram.BotTokenEnv))
	chatID := strings.TrimSpace(os.Getenv(cfg.Telegram.ChatIDEnv))
	if token == "" || chatID == "" {
		log.Printf("remnaguard alerts: telegram env is not configured")
		return
	}
	timeout := cfg.Telegram.Timeout
	if timeout <= 0 {
		timeout = 5 * time.Second
	}
	baseURL := strings.TrimRight(cfg.Telegram.APIBaseURL, "/")
	if baseURL == "" {
		baseURL = "https://api.telegram.org"
	}
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()
	if err := sendTelegram(ctx, m.client, baseURL, token, chatID, formatMessage(b)); err != nil {
		log.Printf("remnaguard alerts: telegram send failed: %v", err)
	}
}

func sendTelegram(ctx context.Context, client *http.Client, baseURL, token, chatID, text string) error {
	payload := map[string]string{"chat_id": chatID, "text": text}
	body, err := json.Marshal(payload)
	if err != nil {
		return err
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, baseURL+"/bot"+token+"/sendMessage", bytes.NewReader(body))
	if err != nil {
		return err
	}
	req.Header.Set("Content-Type", "application/json")
	res, err := client.Do(req)
	if err != nil {
		return err
	}
	defer func() {
		_ = res.Body.Close()
	}()
	if res.StatusCode < 200 || res.StatusCode >= 300 {
		return fmt.Errorf("telegram status %d", res.StatusCode)
	}
	return nil
}

func formatMessage(b bucket) string {
	icon := "🚨"
	if b.event.Status == http.StatusTooManyRequests {
		icon = "⚠️"
	}
	return fmt.Sprintf(
		"%s RemnaGuard deny\n\n"+
			"token: %s\n"+
			"route: %s\n"+
			"reason: %s\n"+
			"status: %d\n\n"+
			"count: %d in %s\n"+
			"first: %s UTC\n"+
			"last: %s UTC",
		icon,
		emptyDash(b.event.TokenID),
		emptyDash(b.event.Route),
		emptyDash(b.event.Reason),
		b.event.Status,
		b.count,
		roundDuration(b.last.Sub(b.first)),
		b.first.UTC().Format("2006-01-02 15:04:05"),
		b.last.UTC().Format("2006-01-02 15:04:05"),
	)
}

func emptyDash(value string) string {
	if strings.TrimSpace(value) == "" {
		return "-"
	}
	return value
}

func roundDuration(d time.Duration) time.Duration {
	if d < time.Second {
		return 0
	}
	return d.Round(time.Second)
}
