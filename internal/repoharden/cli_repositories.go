package repoharden

import (
	"context"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/google/go-github/v88/github"
)

func skipWorkflow(wf *github.Workflow, o *opts) bool {
	if o.includeDynamic {
		return false
	}
	return strings.HasPrefix(wf.GetPath(), dynamicPrefix)
}

func listRepos(ctx context.Context, c *github.Client, o *opts) ([]*github.Repository, error) {
	if o.repo != "" {
		repos, err := getNamedRepos(ctx, c, o.repo)
		if err != nil {
			return nil, err
		}
		for _, repo := range repos {
			if reason := repositoryExclusionReason(repo, o); reason != "" {
				return nil, fmt.Errorf("requested repository %s is excluded: %s", repo.GetFullName(), reason)
			}
		}
		return repos, nil
	}
	var all []*github.Repository
	opts := &github.RepositoryListByAuthenticatedUserOptions{
		Affiliation: "owner,collaborator,organization_member",
		Visibility:  "all",
		ListOptions: github.ListOptions{PerPage: 100},
	}
	pager := githubPager{}
	for {
		repos, resp, err := c.Repositories.ListByAuthenticatedUser(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("list repos: %w", err)
		}
		all = append(all, repos...)
		next, done, err := pager.next(resp)
		if err != nil {
			return nil, fmt.Errorf("list repos: %w", err)
		}
		if done {
			break
		}
		opts.Page = next
	}

	out := all[:0]
	for _, r := range all {
		if repositoryExclusionReason(r, o) != "" {
			continue
		}
		out = append(out, r)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetFullName() < out[j].GetFullName() })
	return out, nil
}

func repositoryExclusionReason(r *github.Repository, o *opts) string {
	if o.owner != "" && !strings.EqualFold(r.GetOwner().GetLogin(), o.owner) {
		return fmt.Sprintf("owner does not match --owner %q", o.owner)
	}
	if r.GetArchived() && !o.includeArchived {
		return "repository is archived (use --include-archived to include it)"
	}
	if r.GetFork() && !o.includeForks {
		return "repository is a fork (use --include-forks to include it)"
	}
	if o.adminOnly && !r.GetPermissions().GetAdmin() {
		return "token does not have admin permission required by --admin-only"
	}
	return ""
}

func getNamedRepos(ctx context.Context, c *github.Client, csv string) ([]*github.Repository, error) {
	var out []*github.Repository
	seen := map[string]bool{}
	for _, item := range strings.Split(csv, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if err := validateRepoSlug(item); err != nil {
			return nil, fmt.Errorf("invalid --repo value: %w", err)
		}
		owner, name := splitRepo(item)
		key := owner + "/" + name
		if seen[key] {
			continue
		}
		seen[key] = true
		r, _, err := c.Repositories.Get(ctx, owner, name)
		if err != nil {
			return nil, fmt.Errorf("get repo %s: %w", key, err)
		}
		out = append(out, r)
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("--repo had no valid owner/repo entries")
	}
	sort.Slice(out, func(i, j int) bool { return out[i].GetFullName() < out[j].GetFullName() })
	return out, nil
}

func requestedRepoSet(csv string) (map[string]bool, error) {
	repos := map[string]bool{}
	for _, item := range strings.Split(csv, ",") {
		item = strings.TrimSpace(item)
		if item == "" {
			continue
		}
		if err := validateRepoSlug(item); err != nil {
			return nil, fmt.Errorf("invalid --repo value: %w", err)
		}
		repos[strings.ToLower(item)] = true
	}
	if csv != "" && len(repos) == 0 {
		return nil, fmt.Errorf("--repo had no valid owner/repo entries")
	}
	return repos, nil
}

func listWorkflows(ctx context.Context, c *github.Client, owner, name string) ([]*github.Workflow, error) {
	var all []*github.Workflow
	opts := &github.ListOptions{PerPage: 100}
	pager := githubPager{}
	for {
		wfs, resp, err := c.Actions.ListWorkflows(ctx, owner, name, opts)
		if err != nil {
			if resp != nil && resp.StatusCode == http.StatusNotFound {
				return nil, nil
			}
			return nil, err
		}
		all = append(all, wfs.Workflows...)
		next, done, err := pager.next(resp)
		if err != nil {
			return nil, fmt.Errorf("list workflows for %s/%s: %w", owner, name, err)
		}
		if done {
			break
		}
		opts.Page = next
	}
	return all, nil
}
