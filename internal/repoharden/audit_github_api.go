package repoharden

import (
	"context"
	"fmt"
	"net/http"

	"github.com/google/go-github/v88/github"
)

const maxGitHubPages = 1000

type githubPager struct {
	current int
	pages   int
}

func (p *githubPager) next(resp *github.Response) (next int, done bool, err error) {
	p.pages++
	if p.pages > maxGitHubPages {
		return 0, false, fmt.Errorf("github pagination exceeded %d pages", maxGitHubPages)
	}
	if resp == nil || resp.NextPage == 0 {
		return 0, true, nil
	}
	current := p.current
	if current == 0 {
		current = 1
	}
	if resp.NextPage <= current {
		return 0, false, fmt.Errorf("github pagination did not advance after page %d (next page %d)", current, resp.NextPage)
	}
	p.current = resp.NextPage
	return p.current, false, nil
}

func githubRawGet(ctx context.Context, c *github.Client, path string, out any) error {
	req, err := c.NewRequest(ctx, http.MethodGet, path, nil)
	if err != nil {
		return err
	}
	if _, err := c.Do(req, out); err != nil {
		return err
	}
	return nil
}

const maxDetailItems = 5

func limitStrings(in []string, n int) []string {
	if len(in) <= n {
		return in
	}
	out := append([]string{}, in[:n]...)
	out = append(out, fmt.Sprintf("+%d more", len(in)-n))
	return out
}

func listGitHubEnvironments(ctx context.Context, c *github.Client, owner, name string) ([]*github.Environment, error) {
	var all []*github.Environment
	opts := &github.EnvironmentListOptions{ListOptions: github.ListOptions{PerPage: 100}}
	var pager githubPager
	for {
		envs, resp, err := c.Repositories.ListEnvironments(ctx, owner, name, opts)
		if err != nil {
			return nil, err
		}
		if envs != nil {
			all = append(all, envs.Environments...)
		}
		next, done, pageErr := pager.next(resp)
		if pageErr != nil {
			return nil, pageErr
		}
		if done {
			return all, nil
		}
		opts.Page = next
	}
}

func listGitHubRepoSecrets(ctx context.Context, c *github.Client, owner, name string) ([]*github.Secret, int, error) {
	var all []*github.Secret
	total := 0
	opts := &github.ListOptions{PerPage: 100}
	var pager githubPager
	for {
		secrets, resp, err := c.Actions.ListRepoSecrets(ctx, owner, name, opts)
		if err != nil {
			return nil, 0, err
		}
		if secrets != nil {
			total = secrets.TotalCount
			all = append(all, secrets.Secrets...)
		}
		next, done, pageErr := pager.next(resp)
		if pageErr != nil {
			return nil, 0, pageErr
		}
		if done {
			break
		}
		opts.Page = next
	}
	if total > len(all) {
		return nil, 0, fmt.Errorf("secrets pagination ended with %d of %d advertised secrets", len(all), total)
	}
	return all, len(all), nil
}

func listGitHubDeployKeys(ctx context.Context, c *github.Client, owner, name string) ([]*github.Key, error) {
	var all []*github.Key
	opts := &github.ListOptions{PerPage: 100}
	var pager githubPager
	for {
		keys, resp, err := c.Repositories.ListKeys(ctx, owner, name, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, keys...)
		next, done, pageErr := pager.next(resp)
		if pageErr != nil {
			return nil, pageErr
		}
		if done {
			return all, nil
		}
		opts.Page = next
	}
}

func listGitHubHooks(ctx context.Context, c *github.Client, owner, name string) ([]*github.Hook, error) {
	var all []*github.Hook
	opts := &github.ListOptions{PerPage: 100}
	var pager githubPager
	for {
		hooks, resp, err := c.Repositories.ListHooks(ctx, owner, name, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, hooks...)
		next, done, pageErr := pager.next(resp)
		if pageErr != nil {
			return nil, pageErr
		}
		if done {
			return all, nil
		}
		opts.Page = next
	}
}

func listGitHubCollaborators(ctx context.Context, c *github.Client, owner, name string, base github.ListCollaboratorsOptions) ([]*github.User, error) {
	var all []*github.User
	opts := base
	opts.ListOptions = github.ListOptions{PerPage: 100}
	var pager githubPager
	for {
		users, resp, err := c.Repositories.ListCollaborators(ctx, owner, name, &opts)
		if err != nil {
			return nil, err
		}
		all = append(all, users...)
		next, done, pageErr := pager.next(resp)
		if pageErr != nil {
			return nil, pageErr
		}
		if done {
			return all, nil
		}
		opts.ListOptions.Page = next
	}
}

func listGitHubDependabotAlerts(ctx context.Context, c *github.Client, owner, name string) ([]*github.DependabotAlert, error) {
	var all []*github.DependabotAlert
	opts := &github.ListAlertsOptions{State: github.Ptr("open"), ListOptions: github.ListOptions{PerPage: 100}}
	var pager githubPager
	for {
		alerts, resp, err := c.Dependabot.ListRepoAlerts(ctx, owner, name, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, alerts...)
		next, done, pageErr := pager.next(resp)
		if pageErr != nil {
			return nil, pageErr
		}
		if done {
			return all, nil
		}
		opts.ListOptions.Page = next
	}
}

func listGitHubCodeScanningAlerts(ctx context.Context, c *github.Client, owner, name string) ([]*github.Alert, error) {
	var all []*github.Alert
	opts := &github.AlertListOptions{State: "open", ListOptions: github.ListOptions{PerPage: 100}}
	var pager githubPager
	for {
		alerts, resp, err := c.CodeScanning.ListAlertsForRepo(ctx, owner, name, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, alerts...)
		next, done, pageErr := pager.next(resp)
		if pageErr != nil {
			return nil, pageErr
		}
		if done {
			return all, nil
		}
		opts.ListOptions.Page = next
	}
}

func listGitHubSecretScanningAlerts(ctx context.Context, c *github.Client, owner, name string) ([]*github.SecretScanningAlert, error) {
	var all []*github.SecretScanningAlert
	opts := &github.SecretScanningAlertListOptions{State: "open", ListOptions: github.ListOptions{PerPage: 100}}
	var pager githubPager
	for {
		alerts, resp, err := c.SecretScanning.ListAlertsForRepo(ctx, owner, name, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, alerts...)
		next, done, pageErr := pager.next(resp)
		if pageErr != nil {
			return nil, pageErr
		}
		if done {
			return all, nil
		}
		opts.ListOptions.Page = next
	}
}

func listGitHubOrgSecrets(ctx context.Context, c *github.Client, org string) ([]*github.Secret, int, error) {
	var all []*github.Secret
	total := 0
	opts := &github.ListOptions{PerPage: 100}
	var pager githubPager
	for {
		secrets, resp, err := c.Actions.ListOrgSecrets(ctx, org, opts)
		if err != nil {
			return nil, 0, err
		}
		if secrets != nil {
			total = secrets.TotalCount
			all = append(all, secrets.Secrets...)
		}
		next, done, pageErr := pager.next(resp)
		if pageErr != nil {
			return nil, 0, pageErr
		}
		if done {
			break
		}
		opts.Page = next
	}
	if total > len(all) {
		return nil, 0, fmt.Errorf("secrets pagination ended with %d of %d advertised secrets", len(all), total)
	}
	return all, len(all), nil
}

func listGitHubOrgHooks(ctx context.Context, c *github.Client, org string) ([]*github.Hook, error) {
	var all []*github.Hook
	opts := &github.ListOptions{PerPage: 100}
	var pager githubPager
	for {
		hooks, resp, err := c.Organizations.ListHooks(ctx, org, opts)
		if err != nil {
			return nil, err
		}
		all = append(all, hooks...)
		next, done, pageErr := pager.next(resp)
		if pageErr != nil {
			return nil, pageErr
		}
		if done {
			return all, nil
		}
		opts.Page = next
	}
}
