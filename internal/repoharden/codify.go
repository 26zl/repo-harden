package repoharden

import (
	"context"
	_ "embed"
	"fmt"
	"sort"
	"strings"
	"text/template"

	"github.com/google/go-github/v88/github"
	"golang.org/x/sync/errgroup"
)

// codify emits the baseline as Terraform/OpenTofu HCL, mirroring the values
// the baseline Apply funcs set — keep the template in sync with controls.go.

//go:embed templates/codify.tf
var codifyTemplateText string

var codifyTemplate = template.Must(template.New("codify").
	Funcs(template.FuncMap{"hcl": hclEscape, "hclStrings": hclStringList}).
	Parse(codifyTemplateText))

// hclEscape escapes a value for use inside a double-quoted HCL string.
func hclEscape(s string) string {
	s = strings.ReplaceAll(s, `\`, `\\`)
	s = strings.ReplaceAll(s, `"`, `\"`)
	s = strings.ReplaceAll(s, "${", "$${")
	s = strings.ReplaceAll(s, "%{", "%%{")
	return s
}

func hclStringList(values []string) string {
	escaped := make([]string, len(values))
	for i, value := range values {
		escaped[i] = `"` + hclEscape(value) + `"`
	}
	return "[" + strings.Join(escaped, ", ") + "]"
}

type codifyRepo struct {
	Name               string
	TFName             string
	OwnerTFName        string
	RulesetID          int64 // 0 = managed ruleset absent; resource is emitted without an import block
	ActionsEnabled     bool
	ActionsPolicy      string
	ActionsSHAPinning  bool
	ActionsSelected    bool
	ActionsGithubOwned bool
	ActionsVerified    bool
	ActionsPatterns    []string
}

type codifyOwner struct {
	Login  string
	TFName string
	Repos  []codifyRepo
}

type codifyData struct {
	Version     string
	RulesetName string
	Owners      []codifyOwner
}

// tfName converts a GitHub login or repo name into a valid Terraform identifier.
func tfName(s string) string {
	var b strings.Builder
	for _, r := range s {
		switch {
		case r >= 'a' && r <= 'z', r >= 'A' && r <= 'Z', r >= '0' && r <= '9', r == '_', r == '-':
			b.WriteRune(r)
		default:
			b.WriteByte('_')
		}
	}
	out := b.String()
	if out == "" || !(out[0] == '_' || (out[0] >= 'a' && out[0] <= 'z') || (out[0] >= 'A' && out[0] <= 'Z')) {
		out = "r_" + out
	}
	return out
}

func buildCodifyData(ctx context.Context, c *github.Client, o *opts, repos []*github.Repository) (codifyData, error) {
	type repoResult struct {
		owner, name string
		rulesetID   int64
		actions     codifyActionsPolicy
	}
	results := make([]repoResult, len(repos))
	g, gctx := errgroup.WithContext(ctx)
	g.SetLimit(max(1, o.concurrency))
	for i, r := range repos {
		g.Go(func() error {
			owner, name := splitRepo(r.GetFullName())
			res := repoResult{owner: owner, name: name}
			sets, err := allRepoRulesets(gctx, c, owner, name, false)
			switch {
			case err == nil:
				matched := 0
				for _, rs := range sets {
					if rs.Name == controlRulesetName {
						matched++
						res.rulesetID = rs.GetID()
						full, _, getErr := c.Repositories.GetRuleset(gctx, owner, name, rs.GetID(), false)
						if getErr != nil {
							return fmt.Errorf("%s: read managed ruleset %d: %w", r.GetFullName(), rs.GetID(), getErr)
						}
						if !rulesetMatchesManagedSpec(full) {
							return fmt.Errorf("%s: refusing to import same-name ruleset %q because generated HCL would overwrite non-baseline rules, conditions, or bypass actors", r.GetFullName(), controlRulesetName)
						}
					}
				}
				if matched > 1 {
					return fmt.Errorf("%s: multiple rulesets named %q; refusing an ambiguous import", r.GetFullName(), controlRulesetName)
				}
			default:
				return fmt.Errorf("%s: list rulesets: %w", r.GetFullName(), err)
			}
			res.actions, err = readCodifyActionsPolicy(gctx, c, owner, name)
			if err != nil {
				return fmt.Errorf("%s: %w", r.GetFullName(), err)
			}
			results[i] = res
			return nil
		})
	}
	if err := g.Wait(); err != nil {
		return codifyData{}, err
	}
	byOwner := map[string][]repoResult{}
	for _, res := range results {
		byOwner[res.owner] = append(byOwner[res.owner], res)
	}
	owners := make([]string, 0, len(byOwner))
	for owner := range byOwner {
		owners = append(owners, owner)
	}
	sort.Strings(owners)
	// sanitized names can collide (a.b vs a_b), so suffix duplicates deterministically
	uniqueName := func(used map[string]bool, base string) string {
		name := base
		for i := 2; used[name]; i++ {
			name = fmt.Sprintf("%s_%d", base, i)
		}
		used[name] = true
		return name
	}
	usedAliases := map[string]bool{}
	usedRepoNames := map[string]bool{}
	data := codifyData{Version: Version, RulesetName: controlRulesetName}
	for _, owner := range owners {
		ownerRepos := byOwner[owner]
		sort.Slice(ownerRepos, func(i, j int) bool { return ownerRepos[i].name < ownerRepos[j].name })
		alias := uniqueName(usedAliases, tfName(owner))
		co := codifyOwner{Login: owner, TFName: alias}
		for _, res := range ownerRepos {
			co.Repos = append(co.Repos, codifyRepo{
				Name:               res.name,
				TFName:             uniqueName(usedRepoNames, tfName(res.owner+"_"+res.name)),
				OwnerTFName:        alias,
				RulesetID:          res.rulesetID,
				ActionsEnabled:     res.actions.enabled,
				ActionsPolicy:      res.actions.allowedActions,
				ActionsSHAPinning:  res.actions.shaPinning,
				ActionsSelected:    res.actions.allowedActions == "selected",
				ActionsGithubOwned: res.actions.githubOwned,
				ActionsVerified:    res.actions.verified,
				ActionsPatterns:    res.actions.patterns,
			})
		}
		data.Owners = append(data.Owners, co)
	}
	return data, nil
}

type codifyActionsPolicy struct {
	enabled, shaPinning, githubOwned, verified bool
	allowedActions                             string
	patterns                                   []string
}

func readCodifyActionsPolicy(ctx context.Context, c *github.Client, owner, name string) (codifyActionsPolicy, error) {
	permissions, _, err := c.Repositories.GetActionsPermissions(ctx, owner, name)
	if err != nil {
		return codifyActionsPolicy{}, fmt.Errorf("read Actions permissions: %w", err)
	}
	if permissions == nil || permissions.Enabled == nil {
		return codifyActionsPolicy{}, fmt.Errorf("read Actions permissions: incomplete response")
	}
	if !permissions.GetEnabled() {
		return codifyActionsPolicy{}, nil // Actions disabled: emit enabled=false without an allowed_actions_config
	}
	if permissions.GetAllowedActions() == "" {
		return codifyActionsPolicy{}, fmt.Errorf("read Actions permissions: incomplete response")
	}
	policy := codifyActionsPolicy{
		enabled:        permissions.GetEnabled(),
		allowedActions: permissions.GetAllowedActions(),
		shaPinning:     permissions.GetSHAPinningRequired(),
	}
	switch policy.allowedActions {
	case "all":
		policy.allowedActions = "selected"
		policy.shaPinning = true
		policy.githubOwned = true
		policy.verified = true
	case "local_only":
		// Preserve a policy that is narrower than the generated selected baseline.
	case "selected":
		allowed, _, getErr := c.Repositories.GetActionsAllowed(ctx, owner, name)
		if getErr != nil {
			return codifyActionsPolicy{}, fmt.Errorf("read selected Actions policy: %w", getErr)
		}
		if allowed == nil {
			return codifyActionsPolicy{}, fmt.Errorf("read selected Actions policy: empty response")
		}
		if safe, invalid := explicitActionPatterns(allowed.PatternsAllowed); !safe {
			return codifyActionsPolicy{}, fmt.Errorf("refusing to codify broad or malformed Actions patterns: %s", strings.Join(invalid, ", "))
		}
		policy.shaPinning = true
		policy.githubOwned = true // mirror Apply, which always allows GitHub-owned actions
		policy.verified = allowed.GetVerifiedAllowed()
		policy.patterns = append([]string(nil), allowed.PatternsAllowed...)
		sort.Strings(policy.patterns)
	default:
		return codifyActionsPolicy{}, fmt.Errorf("unsupported Actions allowed_actions value %q", policy.allowedActions)
	}
	return policy, nil
}

func codifyHCL(data codifyData) (string, error) {
	var b strings.Builder
	if err := codifyTemplate.Execute(&b, data); err != nil {
		return "", err
	}
	return b.String(), nil
}

func cmdCodify(ctx context.Context, c *github.Client, o *opts) error {
	repos, err := listRepos(ctx, c, o)
	if err != nil {
		return err
	}
	if len(repos) == 0 {
		return fmt.Errorf("no repositories matched")
	}
	data, err := buildCodifyData(ctx, c, o, repos)
	if err != nil {
		return err
	}
	out, err := codifyHCL(data)
	if err != nil {
		return err
	}
	stopSpinner()
	fmt.Print(out)
	return nil
}
