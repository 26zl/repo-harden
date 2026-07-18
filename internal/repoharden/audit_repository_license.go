package repoharden

import (
	"context"
	"fmt"
	"net/http"
	"net/url"
	"sort"
	"strings"

	"github.com/google/go-github/v88/github"
)

const (
	repositoryLicenseTitle       = "Repository license is declared"
	repositoryLicenseRemediation = "Add a LICENSE file with a clearly identified SPDX license on the default branch."
)

func auditGitHubRepositoryLicense(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	license, _, err := c.Repositories.License(ctx, owner, name)
	if err != nil {
		if githubStatus(err) == http.StatusNotFound {
			return githubAuditRow(repo, "repository-license", repositoryLicenseTitle, "low", StatusGap,
				"no recognizable repository license", repositoryLicenseRemediation)
		}
		if endpointUnavailable(err) {
			return githubAuditRow(repo, "repository-license", repositoryLicenseTitle, "low", StatusSkipped,
				"repository license API unavailable", repositoryLicenseRemediation)
		}
		return githubAuditRow(repo, "repository-license", repositoryLicenseTitle, "low", StatusError,
			err.Error(), repositoryLicenseRemediation)
	}
	if license == nil || license.License == nil {
		return githubAuditRow(repo, "repository-license", repositoryLicenseTitle, "low", StatusGap,
			"license response did not identify a license", repositoryLicenseRemediation)
	}
	spdx := strings.TrimSpace(license.License.GetSPDXID())
	if spdx == "" || strings.EqualFold(spdx, "NOASSERTION") {
		detail := "license file found but its SPDX license is unknown"
		if path := strings.TrimSpace(license.GetPath()); path != "" {
			detail += ": " + path
		}
		return githubAuditRow(repo, "repository-license", repositoryLicenseTitle, "low", StatusGap,
			detail, repositoryLicenseRemediation)
	}
	return githubAuditRow(repo, "repository-license", repositoryLicenseTitle, "low", StatusCompliant,
		formatDetectedLicense(license.License.GetName(), spdx, license.GetPath()), repositoryLicenseRemediation)
}

func auditGitLabRepositoryLicense(ctx context.Context, c *restClient, p gitlabProject) auditRow {
	var out struct {
		LicenseURL string `json:"license_url"`
		License    *struct {
			Key  string `json:"key"`
			Name string `json:"name"`
		} `json:"license"`
	}
	_, err := c.get(ctx, gitlabProjectPath(p, ""), url.Values{"license": []string{"true"}}, &out)
	if err != nil {
		if httpUnavailable(err) {
			return providerRow("gitlab", "repo", p.PathWithNamespace, "repository-license", repositoryLicenseTitle, "low", StatusSkipped,
				"project license metadata is unavailable", repositoryLicenseRemediation)
		}
		return providerRow("gitlab", "repo", p.PathWithNamespace, "repository-license", repositoryLicenseTitle, "low", StatusError,
			err.Error(), repositoryLicenseRemediation)
	}
	if out.License == nil || (strings.TrimSpace(out.License.Key) == "" && strings.TrimSpace(out.License.Name) == "") {
		return providerRow("gitlab", "repo", p.PathWithNamespace, "repository-license", repositoryLicenseTitle, "low", StatusGap,
			"no recognizable repository license", repositoryLicenseRemediation)
	}
	if unknownLicenseIdentifier(out.License.Key) {
		return providerRow("gitlab", "repo", p.PathWithNamespace, "repository-license", repositoryLicenseTitle, "low", StatusGap,
			"license metadata is present but the license is unknown", repositoryLicenseRemediation)
	}
	return providerRow("gitlab", "repo", p.PathWithNamespace, "repository-license", repositoryLicenseTitle, "low", StatusCompliant,
		formatDetectedLicense(out.License.Name, out.License.Key, ""), repositoryLicenseRemediation)
}

func auditGiteaRepositoryLicense(ctx context.Context, c *restClient, provider string, repo giteaRepo) auditRow {
	if repo.DefaultBranch == "" {
		return providerRow(provider, "repo", repo.FullName, "repository-license", repositoryLicenseTitle, "low", StatusSkipped,
			"no default branch", repositoryLicenseRemediation)
	}
	var entries []struct {
		Name string `json:"name"`
		Path string `json:"path"`
		Type string `json:"type"`
	}
	_, err := c.get(ctx, giteaRepoPath(repo, "/contents"), url.Values{"ref": []string{repo.DefaultBranch}}, &entries)
	if err != nil {
		if httpUnavailable(err) {
			return providerRow(provider, "repo", repo.FullName, "repository-license", repositoryLicenseTitle, "low", StatusSkipped,
				"repository root contents are unavailable", repositoryLicenseRemediation)
		}
		return providerRow(provider, "repo", repo.FullName, "repository-license", repositoryLicenseTitle, "low", StatusError,
			err.Error(), repositoryLicenseRemediation)
	}
	var files []string
	for _, entry := range entries {
		if entry.Type != "" && !strings.EqualFold(entry.Type, "file") {
			continue
		}
		name := strings.TrimSpace(entry.Name)
		if name == "" {
			name = strings.TrimSpace(entry.Path)
		}
		if repositoryLicenseFilename(name) {
			files = append(files, name)
		}
	}
	if len(files) == 0 {
		return providerRow(provider, "repo", repo.FullName, "repository-license", repositoryLicenseTitle, "low", StatusGap,
			"no repository license file found", repositoryLicenseRemediation)
	}
	sort.Strings(files)
	return providerRow(provider, "repo", repo.FullName, "repository-license", repositoryLicenseTitle, "low", StatusCompliant,
		"license file present: "+strings.Join(limitStrings(files, maxDetailItems), ", ")+" (license family not identified by provider)",
		repositoryLicenseRemediation)
}

func repositoryLicenseFilename(path string) bool {
	name := strings.ToUpper(strings.TrimSpace(path))
	if i := strings.LastIndexAny(name, "/\\"); i >= 0 {
		name = name[i+1:]
	}
	for _, base := range []string{"LICENSE", "LICENCE", "COPYING"} {
		if name == base || strings.HasPrefix(name, base+".") || strings.HasPrefix(name, base+"-") {
			return true
		}
	}
	return false
}

func formatDetectedLicense(name, identifier, path string) string {
	name = strings.TrimSpace(name)
	identifier = strings.TrimSpace(identifier)
	path = strings.TrimSpace(path)
	detail := "detected license"
	switch {
	case name != "" && identifier != "" && !strings.EqualFold(name, identifier):
		detail += fmt.Sprintf(": %s (%s)", name, identifier)
	case identifier != "":
		detail += ": " + identifier
	case name != "":
		detail += ": " + name
	}
	if path != "" {
		detail += "; file: " + path
	}
	return detail
}

func unknownLicenseIdentifier(identifier string) bool {
	switch strings.ToUpper(strings.TrimSpace(identifier)) {
	case "OTHER", "UNKNOWN", "NOASSERTION":
		return true
	default:
		return false
	}
}
