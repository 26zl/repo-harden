package repoharden

import (
	"context"
	"fmt"
	"os"

	"github.com/google/go-github/v88/github"
)

type commandHandler func(context.Context, *github.Client, *opts, []string) error

type commandClientRequirement uint8

const (
	commandClientNone commandClientRequirement = iota
	commandClientGitHub
	commandClientGitHubProvider
)

type commandSpec struct {
	name            string
	aliases         []string
	handler         commandHandler
	client          commandClientRequirement
	githubOnly      bool
	showBanner      bool
	showSpinner     bool
	skipFlagParsing bool
	skipValidation  bool
}

// commandRegistry is the single source of truth for command recognition,
// client requirements, presentation, and dispatch.
var commandRegistry = []commandSpec{
	{
		name: "list", client: commandClientGitHub, githubOnly: true, showBanner: true, showSpinner: true,
		handler: func(ctx context.Context, client *github.Client, o *opts, _ []string) error {
			return cmdList(ctx, client, o)
		},
	},
	{
		name: "disable-all", client: commandClientGitHub, githubOnly: true, showBanner: true, showSpinner: true,
		handler: func(ctx context.Context, client *github.Client, o *opts, _ []string) error {
			return cmdDisableAll(ctx, client, o)
		},
	},
	{
		name: "enable-all", client: commandClientGitHub, githubOnly: true, showBanner: true, showSpinner: true,
		handler: func(ctx context.Context, client *github.Client, o *opts, _ []string) error {
			return cmdEnableAll(ctx, client, o)
		},
	},
	{
		name: "enable-all-disabled", client: commandClientGitHub, githubOnly: true, showBanner: true, showSpinner: true,
		handler: func(ctx context.Context, client *github.Client, o *opts, _ []string) error {
			return cmdEnableAllDisabled(ctx, client, o)
		},
	},
	{
		name: "disable-repo", client: commandClientGitHub, githubOnly: true, showBanner: true, showSpinner: true,
		handler: func(ctx context.Context, client *github.Client, o *opts, args []string) error {
			return cmdToggleRepo(ctx, client, o, args, "disable")
		},
	},
	{
		name: "enable-repo", client: commandClientGitHub, githubOnly: true, showBanner: true, showSpinner: true,
		handler: func(ctx context.Context, client *github.Client, o *opts, args []string) error {
			return cmdToggleRepo(ctx, client, o, args, "enable")
		},
	},
	{
		name: "status", client: commandClientGitHub, githubOnly: true, showBanner: true, showSpinner: true,
		handler: func(ctx context.Context, client *github.Client, o *opts, _ []string) error {
			return cmdStatus(ctx, client, o)
		},
	},
	{
		name: "audit", client: commandClientGitHubProvider, showBanner: true, showSpinner: true,
		handler: func(ctx context.Context, client *github.Client, o *opts, _ []string) error {
			return cmdAudit(ctx, client, o)
		},
	},
	{
		name: "harden", client: commandClientGitHub, githubOnly: true, showBanner: true, showSpinner: true,
		handler: func(ctx context.Context, client *github.Client, o *opts, _ []string) error {
			return cmdHarden(ctx, client, o)
		},
	},
	{
		name: "revert", client: commandClientGitHub, githubOnly: true, showBanner: true, showSpinner: true,
		handler: func(ctx context.Context, client *github.Client, o *opts, _ []string) error {
			return cmdRevert(ctx, client, o)
		},
	},
	{
		name: "controls", client: commandClientNone, githubOnly: true, showBanner: true,
		handler: func(_ context.Context, _ *github.Client, o *opts, _ []string) error {
			return cmdControls(o)
		},
	},
	{
		name: "codify", client: commandClientGitHub, githubOnly: true, showSpinner: true,
		handler: func(ctx context.Context, client *github.Client, o *opts, _ []string) error {
			return cmdCodify(ctx, client, o)
		},
	},
	{
		name: "help", aliases: []string{"-h", "--help"}, client: commandClientNone, skipValidation: true,
		handler: func(_ context.Context, _ *github.Client, _ *opts, _ []string) error {
			usage(os.Stdout)
			return nil
		},
	},
	{
		name: "version", aliases: []string{"-v", "--version"}, client: commandClientNone, skipFlagParsing: true,
		handler: func(_ context.Context, _ *github.Client, _ *opts, _ []string) error {
			fmt.Printf("repo-harden %s (commit %s, built %s)\n", Version, Commit, Date)
			return nil
		},
	},
}

func lookupCommand(name string) (commandSpec, bool) {
	for _, spec := range commandRegistry {
		if name == spec.name {
			return spec, true
		}
		for _, alias := range spec.aliases {
			if name == alias {
				return spec, true
			}
		}
	}
	return commandSpec{}, false
}

func validateCommandRegistry(registry []commandSpec) error {
	seen := map[string]string{}
	for _, spec := range registry {
		if spec.name == "" {
			return fmt.Errorf("command has an empty name")
		}
		if spec.handler == nil {
			return fmt.Errorf("command %q has no handler", spec.name)
		}
		if spec.client > commandClientGitHubProvider {
			return fmt.Errorf("command %q has invalid client requirement %d", spec.name, spec.client)
		}
		for _, name := range append([]string{spec.name}, spec.aliases...) {
			if name == "" {
				return fmt.Errorf("command %q has an empty alias", spec.name)
			}
			if owner, duplicate := seen[name]; duplicate {
				return fmt.Errorf("command name or alias %q is shared by %q and %q", name, owner, spec.name)
			}
			seen[name] = spec.name
		}
	}
	return nil
}

func (spec commandSpec) needsGitHubClient(o *opts) bool {
	switch spec.client {
	case commandClientNone:
		return false
	case commandClientGitHub:
		return true
	case commandClientGitHubProvider:
		return o != nil && o.provider == "github"
	default:
		return false
	}
}

func dispatchCommand(ctx context.Context, spec commandSpec, client *github.Client, o *opts, args []string) error {
	if spec.handler == nil {
		return fmt.Errorf("command %q has no handler", spec.name)
	}
	return spec.handler(ctx, client, o, args)
}

func isKnownCommand(name string) bool {
	_, ok := lookupCommand(name)
	return ok
}

func commandNeedsGitHubClient(name string, o *opts) bool {
	spec, ok := lookupCommand(name)
	return ok && spec.needsGitHubClient(o)
}
