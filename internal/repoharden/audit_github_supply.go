package repoharden

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"sort"
	"strings"

	"github.com/google/go-github/v88/github"
)

var provenanceAssetPatterns = []string{".intoto.jsonl", ".sigstore.json", ".sigstore", ".minisig", ".sig", ".sign", ".asc", ".pem", ".cert", ".crt"}

func auditGitHubReleaseProvenance(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository) auditRow {
	const (
		key   = "release-provenance"
		title = "Latest release has GitHub provenance attestations"
		rem   = "Create a GitHub build-provenance attestation for every release artifact (for example with actions/attest-build-provenance) so consumers can verify what they download (SLSA). Filename-only signature sidecars are not sufficient."
	)
	releases, _, err := c.Repositories.ListReleases(ctx, owner, name, &github.ListOptions{PerPage: 5})
	if err != nil {
		return githubAuditErr(repo, key, title, "medium", err, rem)
	}
	var latest *github.RepositoryRelease
	for _, rel := range releases {
		if !rel.GetDraft() {
			latest = rel
			break
		}
	}
	if latest == nil {
		return githubAuditRow(repo, key, title, "medium", StatusSkipped, "no releases", rem)
	}
	if len(latest.Assets) == 0 {
		return githubAuditRow(repo, key, title, "medium", StatusSkipped, "latest release has no distributed artifacts to verify", rem)
	}
	var artifacts []*github.ReleaseAsset
	for _, asset := range latest.Assets {
		if isProvenanceAssetName(asset.GetName()) {
			continue
		}
		artifacts = append(artifacts, asset)
	}
	if len(artifacts) == 0 {
		return githubAuditRow(repo, key, title, "medium", StatusSkipped, "latest release contains only signature/provenance sidecars and no distributed artifact", rem)
	}
	type attestationResult struct {
		found, unavailable bool
	}
	attestations := map[string]attestationResult{}
	var covered, missing, unknown []string
	for _, asset := range artifacts {
		digest := asset.GetDigest()
		if !validSHA256Digest(digest) {
			unknown = append(unknown, asset.GetName()+" (digest unavailable)")
			continue
		}
		result, ok := attestations[strings.ToLower(digest)]
		if !ok {
			found, unavailable, queryErr := githubAssetHasAttestation(ctx, c, owner, name, digest)
			if queryErr != nil {
				return githubAuditErr(repo, key, title, "medium", queryErr, rem)
			}
			result = attestationResult{found: found, unavailable: unavailable}
			attestations[strings.ToLower(digest)] = result
		}
		switch {
		case result.unavailable:
			unknown = append(unknown, asset.GetName()+" (attestations API unavailable)")
		case result.found:
			covered = append(covered, asset.GetName())
		default:
			missing = append(missing, asset.GetName())
		}
	}
	if len(missing) > 0 {
		return githubAuditRow(repo, key, title, "medium", StatusGap,
			"missing verifiable provenance for "+strings.Join(limitStrings(missing, maxDetailItems), ", "), rem)
	}
	if len(unknown) > 0 {
		return githubAuditRow(repo, key, title, "medium", StatusSkipped,
			"could not verify every release artifact: "+strings.Join(limitStrings(unknown, maxDetailItems), ", "), rem)
	}
	sort.Strings(covered)
	return githubAuditRow(repo, key, title, "medium", StatusCompliant,
		fmt.Sprintf("all %d distributed artifact(s) have verifiable provenance: %s", len(artifacts), strings.Join(limitStrings(covered, maxDetailItems), ", ")), rem)
}

func isProvenanceAssetName(name string) bool {
	lower := strings.ToLower(name)
	for _, suffix := range provenanceAssetPatterns {
		if strings.HasSuffix(lower, suffix) {
			return true
		}
	}
	return false
}

func validSHA256Digest(digest string) bool {
	const prefix = "sha256:"
	if !strings.HasPrefix(strings.ToLower(digest), prefix) || len(digest) != len(prefix)+64 {
		return false
	}
	for _, r := range digest[len(prefix):] {
		if !((r >= '0' && r <= '9') || (r >= 'a' && r <= 'f') || (r >= 'A' && r <= 'F')) {
			return false
		}
	}
	return true
}

func githubAssetHasAttestation(ctx context.Context, c *github.Client, owner, name, digest string) (found, unavailable bool, err error) {
	opts := &github.ListOptions{PerPage: 100}
	var pager githubPager
	for {
		result, resp, listErr := c.Repositories.ListAttestations(ctx, owner, name, digest, opts)
		if listErr != nil {
			if githubStatus(listErr) == http.StatusNotFound {
				return false, false, nil
			}
			if endpointUnavailable(listErr) {
				return false, true, nil
			}
			return false, false, listErr
		}
		if result != nil {
			for _, attestation := range result.Attestations {
				if attestation != nil && attestation.RepositoryID > 0 &&
					attestationBundleMatchesDigest(attestation.Bundle, digest) {
					return true, false, nil
				}
			}
		}
		next, done, pageErr := pager.next(resp)
		if pageErr != nil {
			return false, false, pageErr
		}
		if done {
			return false, false, nil
		}
		opts.Page = next
	}
}

type sigstoreBundleEnvelope struct {
	MediaType            string          `json:"mediaType"`
	VerificationMaterial json.RawMessage `json:"verificationMaterial"`
	DSSEEnvelope         *struct {
		PayloadType string `json:"payloadType"`
		Payload     string `json:"payload"`
		Signatures  []struct {
			Signature string `json:"sig"`
		} `json:"signatures"`
	} `json:"dsseEnvelope"`
}

type inTotoStatement struct {
	Type          string          `json:"_type"`
	PredicateType string          `json:"predicateType"`
	Predicate     json.RawMessage `json:"predicate"`
	Subject       []struct {
		Name   string            `json:"name"`
		Digest map[string]string `json:"digest"`
	} `json:"subject"`
}

// attestationBundleMatchesDigest validates the structural subject binding of a native GitHub attestation — consumers must still cryptographically verify attestations before trusting an artifact.
func attestationBundleMatchesDigest(raw json.RawMessage, digest string) bool {
	if !validSHA256Digest(digest) {
		return false
	}
	var bundle sigstoreBundleEnvelope
	if len(raw) == 0 || json.Unmarshal(raw, &bundle) != nil ||
		!strings.HasPrefix(bundle.MediaType, "application/vnd.dev.sigstore.bundle") ||
		bundle.DSSEEnvelope == nil ||
		bundle.DSSEEnvelope.PayloadType != "application/vnd.in-toto+json" ||
		!nonEmptyJSONObject(bundle.VerificationMaterial) {
		return false
	}
	validSignature := false
	for _, signature := range bundle.DSSEEnvelope.Signatures {
		if decoded, ok := decodeBase64(signature.Signature); ok && len(decoded) > 0 {
			validSignature = true
			break
		}
	}
	if !validSignature {
		return false
	}
	payload, ok := decodeBase64(bundle.DSSEEnvelope.Payload)
	if !ok {
		return false
	}
	var statement inTotoStatement
	if json.Unmarshal(payload, &statement) != nil ||
		statement.Type != "https://in-toto.io/Statement/v1" ||
		!strings.HasPrefix(statement.PredicateType, "https://slsa.dev/provenance/") ||
		!nonEmptyJSONObject(statement.Predicate) {
		return false
	}
	want := strings.TrimPrefix(strings.ToLower(digest), "sha256:")
	for _, subject := range statement.Subject {
		if strings.TrimSpace(subject.Name) == "" {
			continue
		}
		for algorithm, value := range subject.Digest {
			if strings.EqualFold(algorithm, "sha256") && strings.EqualFold(value, want) {
				return true
			}
		}
	}
	return false
}

func decodeBase64(value string) ([]byte, bool) {
	if strings.TrimSpace(value) == "" {
		return nil, false
	}
	decoded, err := base64.StdEncoding.DecodeString(value)
	if err != nil {
		decoded, err = base64.RawStdEncoding.DecodeString(value)
	}
	return decoded, err == nil
}

func nonEmptyJSONObject(raw json.RawMessage) bool {
	var object map[string]json.RawMessage
	return len(raw) > 0 && json.Unmarshal(raw, &object) == nil && len(object) > 0
}

func auditGitHubMergeQueue(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository, rc *rulesetListCache) auditRow {
	const (
		key   = "merge-queue"
		title = "Merge queue serializes default-branch merges"
		rem   = "Optional: add a merge_queue rule to the default-branch ruleset so concurrent merges are tested in sequence (recommended for busy repos)."
	)
	rules, err := githubActiveRuleTypes(ctx, c, owner, name, repo.GetDefaultBranch(), rc)
	if err != nil {
		return githubAuditErr(repo, key, title, "info", err, rem)
	}
	if rules["merge_queue"] {
		return githubAuditRow(repo, key, title, "info", StatusCompliant, "merge queue rule active on the default branch", rem)
	}
	return githubAuditRow(repo, key, title, "info", StatusGap, "no merge queue on the default branch (optional hardening)", rem)
}

func auditGitHubTagProtection(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository, rc *rulesetListCache) auditRow {
	const (
		key   = "tag-protection"
		title = "Release tags have controlled creation and immutable history"
		rem   = "Add an active v* tag ruleset that restricts creation to a narrow audited bypass actor and blocks deletion and updates."
	)
	sets, err := rc.get(ctx, c, owner, name)
	if err != nil {
		return githubAuditErr(repo, key, title, "low", err, rem)
	}
	var incomplete []string
	for _, rs := range sets {
		if t := rs.GetTarget(); t == nil || *t != github.RulesetTargetTag || rs.Enforcement != github.RulesetEnforcementActive {
			continue
		}
		full, _, getErr := c.Repositories.GetRuleset(ctx, owner, name, rs.GetID(), true)
		if getErr != nil {
			return githubAuditErr(repo, key, title, "low", fmt.Errorf("read tag ruleset %d: %w", rs.GetID(), getErr), rem)
		}
		if full == nil {
			return githubAuditRow(repo, key, title, "low", StatusError, fmt.Sprintf("read tag ruleset %d: empty response", rs.GetID()), rem)
		}
		if !rulesetTargetsReleaseTags(full) {
			continue
		}
		var missing []string
		if full.Rules == nil || full.Rules.Creation == nil {
			missing = append(missing, "creation restriction")
		}
		if full.Rules == nil || full.Rules.Deletion == nil {
			missing = append(missing, "deletion protection")
		}
		if full.Rules == nil || (full.Rules.NonFastForward == nil && full.Rules.Update == nil) {
			missing = append(missing, "update/non-fast-forward protection")
		}
		if ok, issue := narrowAuditedTagBypass(full.BypassActors); !ok {
			missing = append(missing, issue)
		}
		if len(missing) == 0 {
			return githubAuditRow(repo, key, title, "low", StatusCompliant, "active release-tag ruleset with controlled creation and immutable history: "+rs.Name, rem)
		}
		incomplete = append(incomplete, rs.Name+" missing "+strings.Join(missing, " and "))
	}
	if len(incomplete) > 0 {
		return githubAuditRow(repo, key, title, "low", StatusGap, strings.Join(limitStrings(incomplete, maxDetailItems), "; "), rem)
	}
	return githubAuditRow(repo, key, title, "low", StatusGap, "no complete active ruleset covers release tags (release tags can be moved or deleted)", rem)
}

func narrowAuditedTagBypass(actors []*github.BypassActor) (bool, string) {
	if len(actors) == 0 {
		return false, "no narrow audited creation bypass"
	}
	for _, actor := range actors {
		if actor == nil || actor.ActorType == nil || actor.BypassMode == nil || *actor.BypassMode != github.BypassModeAlways {
			return false, "unverifiable or unaudited bypass actor"
		}
		if actor.ActorID == nil || *actor.ActorID <= 0 {
			return false, "bypass actor has no stable identity"
		}
		switch *actor.ActorType {
		case github.BypassActorTypeIntegration, github.BypassActorTypeTeam, github.BypassActorType("User"):
		default:
			return false, "broad repository-role bypass"
		}
	}
	return true, ""
}

func rulesetTargetsReleaseTags(rs *github.RepositoryRuleset) bool {
	if rs.Conditions == nil || rs.Conditions.RefName == nil {
		return true
	}
	conditions := rs.Conditions.RefName
	if len(conditions.Exclude) > 0 {
		return false
	}
	for _, pattern := range conditions.Include {
		switch pattern {
		case "~ALL", "refs/tags/v*", "refs/tags/v**":
			return true
		}
	}
	return false
}

func auditGitHubPushRuleset(ctx context.Context, c *github.Client, owner, name string, repo *github.Repository, rc *rulesetListCache) auditRow {
	const (
		key   = "push-ruleset"
		title = "Push ruleset limits file size or paths"
		rem   = "Optional: add an active push ruleset to block oversized files and sensitive paths at push time."
	)
	sets, err := rc.get(ctx, c, owner, name)
	if err != nil {
		return githubAuditErr(repo, key, title, "info", err, rem)
	}
	for _, rs := range sets {
		if t := rs.GetTarget(); t == nil || *t != github.RulesetTargetPush || rs.Enforcement != github.RulesetEnforcementActive {
			continue
		}
		full, _, getErr := c.Repositories.GetRuleset(ctx, owner, name, rs.GetID(), true)
		if getErr != nil {
			return githubAuditErr(repo, key, title, "info", fmt.Errorf("read push ruleset %d: %w", rs.GetID(), getErr), rem)
		}
		if full == nil {
			return githubAuditRow(repo, key, title, "info", StatusError, fmt.Sprintf("read push ruleset %d: empty response", rs.GetID()), rem)
		}
		if rulesetHasEffectivePushRestriction(full.Rules) {
			return githubAuditRow(repo, key, title, "info", StatusCompliant, "active push ruleset with an effective file restriction: "+rs.Name, rem)
		}
	}
	return githubAuditRow(repo, key, title, "info", StatusGap, "no active push ruleset has a configured file-size, path, path-length, or extension restriction (optional hardening)", rem)
}

func rulesetHasEffectivePushRestriction(rules *github.RepositoryRulesetRules) bool {
	if rules == nil {
		return false
	}
	return (rules.MaxFileSize != nil && rules.MaxFileSize.MaxFileSize > 0) ||
		(rules.MaxFilePathLength != nil && rules.MaxFilePathLength.MaxFilePathLength > 0) ||
		(rules.FilePathRestriction != nil && len(rules.FilePathRestriction.RestrictedFilePaths) > 0) ||
		(rules.FileExtensionRestriction != nil && len(rules.FileExtensionRestriction.RestrictedFileExtensions) > 0)
}
