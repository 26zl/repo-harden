package repoharden

import (
	"bufio"
	"fmt"
	"net/url"
	"os"
	"strings"

	"github.com/cli/go-gh/v2/pkg/auth"
	"github.com/google/go-github/v88/github"
)

func defaultProviderHost(provider string) string {
	switch provider {
	case "gitlab":
		return "gitlab.com"
	case "gitea", "forgejo":
		return "http://localhost:3000"
	case "bitbucket":
		return "api.bitbucket.org"
	default:
		return "github.com"
	}
}

func providerTokenEnvName(provider string) string {
	switch provider {
	case "gitlab":
		return "GITLAB_TOKEN"
	case "gitea":
		return "GITEA_TOKEN"
	case "forgejo":
		return "FORGEJO_TOKEN (or GITEA_TOKEN)"
	case "bitbucket":
		return "BITBUCKET_TOKEN"
	default:
		return "GITHUB_TOKEN"
	}
}

func tokenFromEnv(provider string) string {
	switch provider {
	case "gitlab":
		return os.Getenv("GITLAB_TOKEN")
	case "gitea":
		return os.Getenv("GITEA_TOKEN")
	case "forgejo":
		if token := os.Getenv("FORGEJO_TOKEN"); token != "" {
			return token
		}
		return os.Getenv("GITEA_TOKEN")
	case "bitbucket":
		return os.Getenv("BITBUCKET_TOKEN")
	default:
		return os.Getenv("GITHUB_TOKEN")
	}
}

func newClient(o *opts) (*github.Client, error) {
	host := hostName(o.host)
	token, err := resolveToken(o, host, "github")
	if err != nil {
		return nil, err
	}
	if token == "" {
		return nil, fmt.Errorf("no GitHub token found for %s - run: gh auth login --hostname %s or set GITHUB_TOKEN", host, host)
	}
	hc := newGitHubHTTPClient(token)
	if host == "github.com" {
		return github.NewClient(github.WithHTTPClient(hc))
	}
	apiURL, uploadURL := githubEnterpriseURLs(o.host)
	if err := requireSecureURL(apiURL); err != nil {
		return nil, err
	}
	return github.NewClient(github.WithHTTPClient(hc), github.WithEnterpriseURLs(apiURL, uploadURL))
}

func resolveToken(o *opts, host, provider string) (string, error) {
	if o.tokenStdin {
		line, err := bufio.NewReader(os.Stdin).ReadString('\n')
		if err != nil && line == "" {
			return "", fmt.Errorf("--token-stdin: failed to read token from stdin: %w", err)
		}
		return strings.TrimSpace(line), nil
	}
	if t := strings.TrimSpace(o.token); t != "" {
		return t, nil
	}
	if provider == "github" {
		if t, _ := auth.TokenForHost(host); t != "" {
			return t, nil
		}
	}
	return tokenFromEnv(provider), nil
}

func hostName(hostOrURL string) string {
	trimmed := strings.TrimSpace(hostOrURL)
	if trimmed == "" {
		return "github.com"
	}
	raw := trimmed
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	u, err := url.Parse(raw)
	if err != nil || u.Host == "" {
		return strings.TrimPrefix(strings.TrimPrefix(trimmed, "https://"), "http://")
	}
	return u.Host
}

func providerBaseURL(provider, hostOrURL string) string {
	raw := strings.TrimRight(strings.TrimSpace(hostOrURL), "/")
	if raw == "" {
		raw = defaultProviderHost(provider)
	}
	if !strings.Contains(raw, "://") {
		raw = "https://" + raw
	}
	switch provider {
	case "gitlab":
		raw = strings.TrimSuffix(raw, "/api/v4")
	case "gitea", "forgejo":
		raw = strings.TrimSuffix(raw, "/api/v1")
	case "bitbucket":
		raw = strings.TrimSuffix(raw, "/2.0")
		// The web host serves no REST API; accept it as a shorthand for the API host.
		if u, err := url.Parse(raw); err == nil && (u.Host == "bitbucket.org" || u.Host == "www.bitbucket.org") {
			u.Host = "api.bitbucket.org"
			raw = u.String()
		}
	}
	return raw
}

func githubEnterpriseURLs(hostOrURL string) (string, string) {
	base := strings.TrimRight(providerBaseURL("github", hostOrURL), "/")
	base = strings.TrimSuffix(base, "/api/v3")
	return base + "/api/v3/", base + "/api/uploads/"
}

func splitRepo(fullName string) (owner, name string) {
	i := strings.IndexByte(fullName, '/')
	if i < 0 {
		return "", fullName
	}
	return fullName[:i], fullName[i+1:]
}
