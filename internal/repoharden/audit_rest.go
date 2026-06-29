package repoharden

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"strings"
	"time"
)

type restClient struct {
	baseURL string
	token   string
	header  string
	prefix  string
	client  *http.Client
}

const maxRESTResponseBytes = 16 << 20

func newRestClient(provider string, o *opts) (*restClient, error) {
	token, err := resolveToken(o, o.host, provider)
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, fmt.Errorf("no %s token found for %s", provider, o.host)
	}
	header := "Authorization"
	prefix := "Bearer "
	switch provider {
	case "gitlab":
		header = "PRIVATE-TOKEN"
		prefix = ""
	case "gitea", "forgejo":
		prefix = "token "
	}
	base := providerBaseURL(provider, o.host)
	if err := requireSecureURL(base); err != nil {
		return nil, err
	}
	return &restClient{
		baseURL: base,
		token:   token,
		header:  header,
		prefix:  prefix,
		client: &http.Client{
			Timeout:       30 * time.Second,
			CheckRedirect: noCrossHostRedirect,
			Transport:     &retryTransport{base: http.DefaultTransport, max: 3},
		},
	}, nil
}

type restError struct {
	method     string
	path       string
	statusCode int
	status     string
}

func (e *restError) Error() string {
	return fmt.Sprintf("%s %s: %s", e.method, e.path, e.status)
}

func (c *restClient) get(ctx context.Context, path string, query url.Values, out any) (*http.Response, error) {
	u := strings.TrimRight(c.baseURL, "/") + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return nil, err
	}
	req.Header.Set("Accept", "application/json")
	req.Header.Set(c.header, c.prefix+c.token)
	resp, err := c.client.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return resp, &restError{method: http.MethodGet, path: path, statusCode: resp.StatusCode, status: resp.Status}
	}
	if out == nil {
		return resp, nil
	}
	dec := json.NewDecoder(io.LimitReader(resp.Body, maxRESTResponseBytes))
	if err := dec.Decode(out); err != nil {
		return resp, err
	}
	if err := ensureJSONEOF(dec); err != nil {
		return resp, err
	}
	return resp, nil
}

func providerRow(provider, scope, target, key, title, severity string, status ControlStatus, detail, remediation string) auditRow {
	return auditRow{
		Provider:    provider,
		Scope:       scope,
		Repo:        target,
		Control:     key,
		Title:       title,
		Severity:    severity,
		Status:      string(status),
		Detail:      detail,
		Remediation: remediation,
	}
}

func httpUnavailable(err error) bool {
	if err == nil {
		return false
	}
	var restErr *restError
	if errors.As(err, &restErr) {
		switch restErr.statusCode {
		case http.StatusNotFound, http.StatusMethodNotAllowed, http.StatusGone:
			return true
		}
	}
	return false
}

func requireSecureURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("unsupported URL scheme %q (expected https or loopback http)", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("URL has no host")
	}
	if u.User != nil {
		return errors.New("URL must not contain user information")
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("URL must not contain a query or fragment")
	}
	if u.Scheme == "http" {
		switch u.Hostname() {
		case "localhost", "127.0.0.1", "::1":
		default:
			return fmt.Errorf("refusing to send token over cleartext http to %q; use https", u.Host)
		}
	}
	return nil
}

func escapedPath(parts ...string) string {
	out := make([]string, 0, len(parts))
	for _, part := range parts {
		out = append(out, url.PathEscape(part))
	}
	return strings.Join(out, "/")
}

func escapedFilePath(path string) string {
	parts := strings.Split(path, "/")
	return escapedPath(parts...)
}
