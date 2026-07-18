package repoharden

import (
	"bytes"
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
		return nil, fmt.Errorf("no %s token found for %s - set %s, or pass --token/--token-stdin",
			provider, o.host, providerTokenEnvName(provider))
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
	baseURL, err := url.Parse(base)
	if err != nil {
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
			Transport: &retryTransport{
				base: &hostScopedHeader{header: header, host: baseURL.Host, base: http.DefaultTransport},
				max:  3,
			},
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
	data, err := readLimitedResponse(resp.Body, maxRESTResponseBytes)
	if err != nil {
		return resp, err
	}
	dec := json.NewDecoder(bytes.NewReader(data))
	if err := dec.Decode(out); err != nil {
		return resp, err
	}
	if err := ensureJSONEOF(dec); err != nil {
		return resp, err
	}
	return resp, nil
}

// getText fetches a raw (non-JSON) resource, e.g. a pipeline definition file.
func (c *restClient) getText(ctx context.Context, path string, query url.Values) (string, error) {
	u := strings.TrimRight(c.baseURL, "/") + path
	if len(query) > 0 {
		u += "?" + query.Encode()
	}
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, u, nil)
	if err != nil {
		return "", err
	}
	req.Header.Set(c.header, c.prefix+c.token)
	resp, err := c.client.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode < 200 || resp.StatusCode > 299 {
		return "", &restError{method: http.MethodGet, path: path, statusCode: resp.StatusCode, status: resp.Status}
	}
	data, err := readLimitedResponse(resp.Body, maxRESTResponseBytes)
	if err != nil {
		return "", err
	}
	return string(data), nil
}

func readLimitedResponse(r io.Reader, limit int64) ([]byte, error) {
	if limit < 0 {
		return nil, errors.New("response size limit must be non-negative")
	}
	data, err := io.ReadAll(io.LimitReader(r, limit+1))
	if err != nil {
		return nil, err
	}
	if int64(len(data)) > limit {
		return nil, fmt.Errorf("response exceeds %d-byte safety limit", limit)
	}
	return data, nil
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
	return httpPermissionDenied(err) || httpNotFound(err) || httpUnsupported(err)
}

// Authentication failures are errors, while an authenticated caller that lacks
// a particular permission is an unverifiable audit result.
func httpPermissionDenied(err error) bool {
	return restStatusCode(err) == http.StatusForbidden
}

func httpNotFound(err error) bool {
	return restStatusCode(err) == http.StatusNotFound
}

func httpUnsupported(err error) bool {
	switch restStatusCode(err) {
	case http.StatusMethodNotAllowed, http.StatusGone, http.StatusNotImplemented:
		return true
	default:
		return false
	}
}

func restStatusCode(err error) int {
	var restErr *restError
	if errors.As(err, &restErr) {
		return restErr.statusCode
	}
	return 0
}

func requireSecureURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	if u.RawQuery != "" || u.Fragment != "" {
		return errors.New("URL must not contain a query or fragment")
	}
	return checkSecureURL(u)
}

// requireSecureRedirectURL validates redirect targets while allowing query strings and fragments.
func requireSecureRedirectURL(raw string) error {
	u, err := url.Parse(raw)
	if err != nil {
		return err
	}
	return checkSecureURL(u)
}

func checkSecureURL(u *url.URL) error {
	if u.Scheme != "https" && u.Scheme != "http" {
		return fmt.Errorf("unsupported URL scheme %q (expected https or loopback http)", u.Scheme)
	}
	if u.Host == "" {
		return errors.New("URL has no host")
	}
	if u.User != nil {
		return errors.New("URL must not contain user information")
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
