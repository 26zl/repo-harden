package repoharden

import (
	"context"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"
)

func TestRetryDelayHonorsRetryAfterAndCap(t *testing.T) {
	now := time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC)
	rt := &retryTransport{now: func() time.Time { return now }}
	req, err := http.NewRequest(http.MethodGet, "https://api.github.com/rate", nil)
	if err != nil {
		t.Fatal(err)
	}
	respWith := func(headers map[string]string) *http.Response {
		resp := &http.Response{Header: make(http.Header)}
		for k, v := range headers {
			resp.Header.Set(k, v)
		}
		return resp
	}
	const jitter = 251 * time.Millisecond

	if d := rt.retryDelay(req, respWith(map[string]string{"Retry-After": "7"}), 0); d < 7*time.Second || d > 7*time.Second+jitter {
		t.Errorf("Retry-After seconds: %s, want ~7s", d)
	}
	date := now.Add(30 * time.Second).Format(http.TimeFormat)
	if d := rt.retryDelay(req, respWith(map[string]string{"Retry-After": date}), 0); d < 29*time.Second || d > 30*time.Second+jitter {
		t.Errorf("Retry-After HTTP date: %s, want ~30s", d)
	}
	if d := rt.retryDelay(req, respWith(map[string]string{"Retry-After": "99999"}), 0); d != maxRetryWait {
		t.Errorf("huge Retry-After: %s, want capped at %s", d, maxRetryWait)
	}
	// reset 15 minutes past the fake clock, far beyond the cap
	if d := rt.retryDelay(req, respWith(map[string]string{
		"X-RateLimit-Remaining": "0",
		"X-RateLimit-Reset":     "1767226500",
	}), 0); d != maxRetryWait {
		t.Errorf("rate-limit reset beyond cap: %s, want %s", d, maxRetryWait)
	}
	if d := rt.retryDelay(req, nil, 3); d < 8*time.Second || d > 8*time.Second+jitter {
		t.Errorf("exponential fallback at attempt 3: %s, want ~8s", d)
	}
}

func TestRedirectLoopStopsAtTen(t *testing.T) {
	target, err := url.Parse("https://api.github.com/next")
	if err != nil {
		t.Fatal(err)
	}
	req := &http.Request{URL: target}
	via := make([]*http.Request, 10)
	for i := range via {
		via[i] = req
	}
	if err := noCrossHostRedirect(req, via); err == nil || !strings.Contains(err.Error(), "10 redirects") {
		t.Fatalf("10 prior redirects: err = %v, want redirect-loop stop", err)
	}
	if err := noCrossHostRedirect(req, via[:3]); err != nil {
		t.Fatalf("3 same-host https redirects must be allowed, got %v", err)
	}
}

func TestAuthTransportSetsBearer(t *testing.T) {
	var got string
	at := &authTransport{token: "tok", base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		got = req.Header.Get("Authorization")
		return &http.Response{StatusCode: 200, Header: make(http.Header), Body: http.NoBody}, nil
	})}
	req, _ := http.NewRequest(http.MethodGet, "https://x/y", nil)
	if _, err := at.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	if got != "Bearer tok" {
		t.Fatalf("Authorization = %q, want Bearer tok", got)
	}
}

func TestRetryTransportDoesNotRetryMutations(t *testing.T) {
	calls := 0
	rt := &retryTransport{max: 3, base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		return &http.Response{StatusCode: 500, Header: make(http.Header), Body: http.NoBody}, nil
	})}
	req, _ := http.NewRequest(http.MethodPost, "https://x/y", nil)
	if _, err := rt.RoundTrip(req); err != nil {
		t.Fatal(err)
	}
	if calls != 1 {
		t.Fatalf("POST must not be retried, got %d calls", calls)
	}
}

func TestRetryTransportRetriesGETOn500(t *testing.T) {
	calls := 0
	rt := &retryTransport{max: 3, sleep: func(context.Context, time.Duration) error { return nil }, base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		calls++
		code := http.StatusOK
		if calls == 1 {
			code = http.StatusInternalServerError
		}
		return &http.Response{StatusCode: code, Header: make(http.Header), Body: http.NoBody}, nil
	})}
	req, _ := http.NewRequest(http.MethodGet, "https://x/y", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("got %v / %v, want 200/nil", resp, err)
	}
	if calls != 2 {
		t.Fatalf("expected 1 retry (2 calls), got %d", calls)
	}
}

func TestRetryTransportHonorsPrimaryRateLimitReset(t *testing.T) {
	calls := 0
	var waited time.Duration
	now := time.Unix(1_700_000_000, 0)
	rt := &retryTransport{
		max: 1,
		now: func() time.Time { return now },
		sleep: func(_ context.Context, delay time.Duration) error {
			waited = delay
			return nil
		},
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			if calls == 1 {
				headers := make(http.Header)
				headers.Set("X-RateLimit-Remaining", "0")
				headers.Set("X-RateLimit-Reset", strconv.FormatInt(now.Add(12*time.Second).Unix(), 10))
				return &http.Response{StatusCode: http.StatusForbidden, Header: headers, Body: http.NoBody, Request: req}, nil
			}
			return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
		}),
	}
	req, _ := http.NewRequest(http.MethodGet, "https://api.github.com/repos/me/app", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil || resp.StatusCode != http.StatusOK {
		t.Fatalf("rate-limit retry got %v / %v, want 200/nil", resp, err)
	}
	if calls != 2 {
		t.Fatalf("calls = %d, want 2", calls)
	}
	if waited < 12*time.Second || waited > 13*time.Second {
		t.Fatalf("waited %s, want reset delay plus bounded jitter", waited)
	}
}

func TestRetryTransportStopsWhenDeadlineCannotCoverWait(t *testing.T) {
	calls := 0
	now := time.Unix(1_700_000_000, 0)
	rt := &retryTransport{
		max: 3,
		now: func() time.Time { return now },
		sleep: func(context.Context, time.Duration) error {
			t.Error("must not wait when the deadline cannot cover the retry delay")
			return nil
		},
		base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
			calls++
			headers := make(http.Header)
			headers.Set("Retry-After", "45")
			return &http.Response{StatusCode: http.StatusTooManyRequests, Header: headers, Body: http.NoBody, Request: req}, nil
		}),
	}
	ctx, cancel := context.WithDeadline(context.Background(), now.Add(30*time.Second))
	defer cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://x/y", nil)
	resp, err := rt.RoundTrip(req)
	if err != nil || resp == nil || resp.StatusCode != http.StatusTooManyRequests {
		t.Fatalf("got %v / %v, want the rate-limited response surfaced", resp, err)
	}
	if calls != 1 {
		t.Fatalf("calls = %d, want 1 (no retry past the client timeout)", calls)
	}
}

func TestRetryTransportStopsOnCanceledContext(t *testing.T) {
	rt := &retryTransport{max: 3, base: roundTripFunc(func(req *http.Request) (*http.Response, error) {
		return &http.Response{StatusCode: 500, Header: make(http.Header), Body: http.NoBody}, nil
	})}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	req, _ := http.NewRequestWithContext(ctx, http.MethodGet, "https://x/y", nil)
	if _, err := rt.RoundTrip(req); err == nil {
		t.Fatal("canceled context should abort the retry wait")
	}
}

func TestNoCrossHostRedirect(t *testing.T) {
	orig, _ := http.NewRequest(http.MethodGet, "https://api.github.com/a", nil)
	same, _ := http.NewRequest(http.MethodGet, "https://api.github.com/b", nil)
	if err := noCrossHostRedirect(same, []*http.Request{orig}); err != nil {
		t.Fatalf("same-host redirect should be allowed: %v", err)
	}
	other, _ := http.NewRequest(http.MethodGet, "https://evil.example.com/x", nil)
	if err := noCrossHostRedirect(other, []*http.Request{orig}); err == nil {
		t.Fatal("cross-host redirect must be refused (token would leak)")
	}
}

func TestGitHubClientDoesNotLeakTokenOnCrossHostRedirect(t *testing.T) {
	var leaked string
	attacker := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		leaked = r.Header.Get("Authorization")
	}))
	defer attacker.Close()
	origin := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, attacker.URL+"/stolen", http.StatusFound)
	}))
	defer origin.Close()

	resp, err := newGitHubHTTPClient("secret").Get(origin.URL + "/start")
	if err == nil && resp != nil {
		resp.Body.Close()
	}
	if leaked != "" {
		t.Fatalf("bearer token leaked to redirect target: %q", leaked)
	}
}

func TestRequireSecureRedirectURLAllowsQuery(t *testing.T) {
	if err := requireSecureURL("https://gitlab.example.com/api?page=2"); err == nil {
		t.Fatal("a base URL carrying a query must be rejected")
	}
	if err := requireSecureRedirectURL("https://gitlab.example.com/api?page=2"); err != nil {
		t.Fatalf("a redirect target carrying a query must be allowed: %v", err)
	}
	if err := requireSecureRedirectURL("http://evil.example.com/api"); err == nil {
		t.Fatal("cleartext http to a non-loopback host must still be refused on redirect")
	}
	if err := requireSecureRedirectURL("https://u:p@h.example.com/x"); err == nil {
		t.Fatal("userinfo must still be refused on redirect")
	}
}

func TestSameHostRedirectWithQueryAllowed(t *testing.T) {
	orig, _ := http.NewRequest(http.MethodGet, "https://gitlab.example.com/api/v4/projects", nil)
	target, _ := http.NewRequest(http.MethodGet, "https://gitlab.example.com/api/v4/projects?page=2&per_page=100", nil)
	if err := noCrossHostRedirect(target, []*http.Request{orig}); err != nil {
		t.Fatalf("a same-host redirect carrying a query string must be allowed: %v", err)
	}
}

func TestHostScopedHeaderStripsOffHost(t *testing.T) {
	var seen string
	base := roundTripFunc(func(req *http.Request) (*http.Response, error) {
		seen = req.Header.Get("PRIVATE-TOKEN")
		return &http.Response{StatusCode: http.StatusOK, Header: make(http.Header), Body: http.NoBody, Request: req}, nil
	})
	rt := &hostScopedHeader{header: "PRIVATE-TOKEN", host: "gitlab.example.com", base: base}

	same, _ := http.NewRequest(http.MethodGet, "https://gitlab.example.com/x", nil)
	same.Header.Set("PRIVATE-TOKEN", "secret")
	if _, err := rt.RoundTrip(same); err != nil {
		t.Fatal(err)
	}
	if seen != "secret" {
		t.Fatalf("same-host request should keep the token header, got %q", seen)
	}

	off, _ := http.NewRequest(http.MethodGet, "https://evil.example.com/x", nil)
	off.Header.Set("PRIVATE-TOKEN", "secret")
	if _, err := rt.RoundTrip(off); err != nil {
		t.Fatal(err)
	}
	if seen != "" {
		t.Fatalf("off-host request must have the token header stripped, got %q", seen)
	}
}
