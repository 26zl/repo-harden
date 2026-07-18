package repoharden

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"
)

const maxProviderPages = 1000

func gitlabNextPage(respHeader string, current int) (next int, done bool, err error) {
	if respHeader == "" {
		return 0, true, nil
	}
	next, err = strconv.Atoi(respHeader)
	if err != nil || next <= current {
		return 0, false, fmt.Errorf("invalid GitLab X-Next-Page %q after page %d", respHeader, current)
	}
	return next, false, nil
}

func giteaNextPage(resp *http.Response, current, received, totalSeen int) (next int, done bool, err error) {
	if resp == nil {
		return 0, true, nil
	}
	total := -1
	if rawTotal := strings.TrimSpace(resp.Header.Get("X-Total-Count")); rawTotal != "" {
		var parseErr error
		total, parseErr = strconv.Atoi(rawTotal)
		if parseErr != nil || total < 0 {
			return 0, false, fmt.Errorf("invalid Gitea X-Total-Count %q", rawTotal)
		}
	}
	if link := resp.Header.Get("Link"); link != "" {
		foundNext := false
		for _, part := range strings.Split(link, ",") {
			segments := strings.Split(part, ";")
			if len(segments) < 2 || !strings.Contains(strings.Join(segments[1:], ";"), `rel="next"`) {
				continue
			}
			rawURL := strings.TrimSpace(segments[0])
			if len(rawURL) < 2 || rawURL[0] != '<' || rawURL[len(rawURL)-1] != '>' {
				return 0, false, fmt.Errorf("invalid Gitea pagination Link %q", part)
			}
			u, parseErr := url.Parse(rawURL[1 : len(rawURL)-1])
			if parseErr != nil {
				return 0, false, fmt.Errorf("invalid Gitea pagination Link %q: %w", part, parseErr)
			}
			next, parseErr = strconv.Atoi(u.Query().Get("page"))
			if parseErr != nil || next <= current {
				return 0, false, fmt.Errorf("non-advancing Gitea pagination Link after page %d", current)
			}
			foundNext = true
			break
		}
		if foundNext {
			return next, false, nil
		}
		if total >= 0 && totalSeen < total {
			return 0, false, fmt.Errorf("gitea pagination Link ended after page %d with %d of %d advertised items", current, totalSeen, total)
		}
		return 0, true, nil
	}
	if total >= 0 {
		if totalSeen >= total {
			return 0, true, nil
		}
		if received == 0 {
			return 0, false, fmt.Errorf("gitea pagination stopped after page %d with %d of %d advertised items", current, totalSeen, total)
		}
		return current + 1, false, nil
	}
	if received == 0 {
		return 0, true, nil
	}
	// Some Gitea-compatible servers cap page size below the requested limit, so only an empty page proves completion.
	return current + 1, false, nil
}

func gitlabPaged[T any](ctx context.Context, c *restClient, path string, extra url.Values) ([]T, error) {
	var all []T
	page := 1
	for page <= maxProviderPages {
		q := url.Values{"per_page": []string{"100"}, "page": []string{strconv.Itoa(page)}}
		for k, v := range extra {
			q[k] = v
		}
		var batch []T
		resp, err := c.get(ctx, path, q, &batch)
		if err != nil {
			return nil, err
		}
		all = append(all, batch...)
		next, done, err := gitlabNextPage(resp.Header.Get("X-Next-Page"), page)
		if err != nil {
			return nil, err
		}
		if done {
			return all, nil
		}
		page = next
	}
	return nil, fmt.Errorf("gitlab pagination for %s exceeded %d pages", path, maxProviderPages)
}

func giteaPaged[T any](ctx context.Context, c *restClient, path string) ([]T, error) {
	var all []T
	const limit = 50
	page := 1
	for requests := 1; requests <= maxProviderPages; requests++ {
		var batch []T
		resp, err := c.get(ctx, path, url.Values{"limit": []string{strconv.Itoa(limit)}, "page": []string{strconv.Itoa(page)}}, &batch)
		if err != nil {
			return nil, err
		}
		all = append(all, batch...)
		next, done, err := giteaNextPage(resp, page, len(batch), len(all))
		if err != nil {
			return nil, err
		}
		if done {
			return all, nil
		}
		page = next
	}
	return nil, fmt.Errorf("gitea pagination for %s exceeded %d pages", path, maxProviderPages)
}
