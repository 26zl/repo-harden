package repoharden

import (
	"context"
	"errors"
	"fmt"
	"hash/fnv"
	"net/http"
	"strconv"
	"time"
)

type authTransport struct {
	token string
	base  http.RoundTripper
}

func (t *authTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	req = req.Clone(req.Context())
	req.Header.Set("Authorization", "Bearer "+t.token)
	return t.base.RoundTrip(req)
}

type retryTransport struct {
	base  http.RoundTripper
	max   int
	sleep func(context.Context, time.Duration) error
	now   func() time.Time
}

func (rt *retryTransport) RoundTrip(req *http.Request) (*http.Response, error) {
	if req.Method != http.MethodGet && req.Method != http.MethodHead {
		return rt.base.RoundTrip(req)
	}
	for attempt := 0; ; attempt++ {
		resp, err := rt.base.RoundTrip(req)
		retryableStatus := resp != nil &&
			(resp.StatusCode == http.StatusTooManyRequests ||
				resp.StatusCode >= 500 ||
				(resp.StatusCode == http.StatusForbidden &&
					(resp.Header.Get("Retry-After") != "" || resp.Header.Get("X-RateLimit-Remaining") == "0")))
		if err == nil && !retryableStatus {
			return resp, nil
		}
		if attempt >= rt.max {
			return resp, err
		}
		wait := rt.retryDelay(req, resp, attempt)
		if resp != nil {
			_ = resp.Body.Close()
		}
		if err := rt.wait(req.Context(), wait); err != nil {
			return nil, err
		}
	}
}

const maxRetryWait = 60 * time.Second

func (rt *retryTransport) retryDelay(req *http.Request, resp *http.Response, attempt int) time.Duration {
	wait := time.Duration(1<<attempt) * time.Second
	now := time.Now
	if rt.now != nil {
		now = rt.now
	}
	if resp != nil {
		if retryAfter, err := strconv.Atoi(resp.Header.Get("Retry-After")); err == nil && retryAfter > 0 {
			wait = time.Duration(retryAfter) * time.Second
		} else if retryAt, err := http.ParseTime(resp.Header.Get("Retry-After")); err == nil {
			if until := retryAt.Sub(now()); until > 0 {
				wait = until
			}
		} else if resp.Header.Get("X-RateLimit-Remaining") == "0" {
			if reset, err := strconv.ParseInt(resp.Header.Get("X-RateLimit-Reset"), 10, 64); err == nil {
				if until := time.Unix(reset, 0).Sub(now()); until > 0 {
					wait = until
				}
			}
		}
	}
	// Stable, non-negative jitter prevents a fleet of concurrent workers from
	// retrying at exactly the same instant without making tests nondeterministic.
	h := fnv.New32a()
	_, _ = h.Write([]byte(req.Method + "\x00" + req.URL.String() + "\x00" + strconv.Itoa(attempt)))
	wait += time.Duration(h.Sum32()%251) * time.Millisecond
	if wait > maxRetryWait {
		return maxRetryWait
	}
	return wait
}

func (rt *retryTransport) wait(ctx context.Context, delay time.Duration) error {
	if rt.sleep != nil {
		return rt.sleep(ctx, delay)
	}
	timer := time.NewTimer(delay)
	defer timer.Stop()
	select {
	case <-ctx.Done():
		return ctx.Err()
	case <-timer.C:
		return nil
	}
}

func newGitHubHTTPClient(token string) *http.Client {
	return &http.Client{
		Timeout:       90 * time.Second,
		CheckRedirect: noCrossHostRedirect,
		Transport: &retryTransport{
			base: &authTransport{token: token, base: http.DefaultTransport},
			max:  3,
		},
	}
}

func noCrossHostRedirect(req *http.Request, via []*http.Request) error {
	if len(via) > 0 && req.URL.Host != via[0].URL.Host {
		return fmt.Errorf("refusing cross-host redirect to %s", req.URL.Host)
	}
	if err := requireSecureURL(req.URL.String()); err != nil {
		return err
	}
	if len(via) >= 10 {
		return errors.New("stopped after 10 redirects")
	}
	return nil
}
