/*
Copyright 2021 Adevinta
*/

package generator

import (
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/adevinta/vulcan-agent/jobrunner"
	"github.com/adevinta/vulcan-agent/log"
	"github.com/adevinta/vulcan-agent/queue/sqs"
	"github.com/adevinta/vulcan-local/pkg/config"
	"github.com/adevinta/vulcan-local/pkg/gitservice"
	types "github.com/adevinta/vulcan-types"
	"github.com/google/uuid"
)

func getCheckType(cfg *config.Config, checkTypeRef config.ChecktypeRef) (*config.Checktype, error) {
	if ct, ok := cfg.CheckTypes[checkTypeRef]; ok {
		return &ct, nil
	} else {
		return nil, fmt.Errorf("unable to find checktype ref %s", checkTypeRef)
	}
}

// mergeOptions takes two check options.
func mergeOptions(optsA map[string]interface{}, optsB map[string]interface{}) map[string]interface{} {
	merged := map[string]interface{}{}
	for k, v := range optsA {
		merged[k] = v
	}
	for k, v := range optsB {
		merged[k] = v
	}
	return merged
}

// buildOptions generates a string encoded
func buildOptions(options map[string]interface{}) (string, error) {
	if options == nil {
		return "{}", nil
	}
	content, err := json.Marshal(options)
	if err != nil {
		return "", err
	}
	return string(content), nil
}

func GenerateJobs(cfg *config.Config, agentIp, hostIp string, gs gitservice.GitService, l log.Logger) ([]jobrunner.Job, error) {
	unique := map[string]*config.Check{}

	jobs := []jobrunner.Job{}
	for i := range cfg.Checks {
		// Because We want to update the original Check
		c := &cfg.Checks[i]
		ch, err := getCheckType(cfg, c.Type)
		if err != nil {
			l.Errorf("Skipping check - %s", err)
			continue
		}

		if !filterChecktype(ch.Name, cfg.Conf.IncludeR, cfg.Conf.ExcludeR) {
			l.Debugf("Skipping filtered check=%s", ch.Name)
			continue
		}

		ops, err := buildOptions(c.Options)
		if err != nil {
			l.Errorf("Skipping check - %s", err)
			continue
		}

		c.Id = uuid.New().String()
		c.NewTarget = c.Target
		if stringInSlice("GitRepository", ch.Assets) {
			if path, err := GetValidGitDirectory(c.Target); err == nil {
				c.AssetType = "GitRepository"
				port, err := gs.AddGit(path)
				if err != nil {
					l.Errorf("Unable to create local git server check %w", err)
					continue
				}
				c.NewTarget = fmt.Sprintf("http://%s:%d/", agentIp, port)
			}
		}
		m1 := regexp.MustCompile(`(?i)(localhost|127.0.0.1)`)
		c.NewTarget = m1.ReplaceAllString(c.NewTarget, hostIp)

		// We allow all the checks to scan local assets.
		// This could be tunned depending on the target/assettype
		vars := append(ch.RequiredVars, "VULCAN_ALLOW_PRIVATE_IPS")

		fingerprint := ComputeFingerprint(ch.Image, c.Target, c.AssetType, ops)
		if dup, ok := unique[fingerprint]; ok {
			l.Debugf("Filtering duplicated check name=%s image=%s target=%s id=%s id=%s", ch.Name, ch.Image, c.Target, c.Id, dup.Id)
			continue
		}
		unique[fingerprint] = c

		l.Infof("Check name=%s image=%s target=%s new=%s type=%s id=%s", ch.Name, ch.Image, c.Target, c.NewTarget, c.AssetType, c.Id)

		// Store the checkType for traceability
		c.Checktype = ch

		timeout := ch.Timeout
		if c.Timeout != nil {
			timeout = *c.Timeout
		}
		jobs = append(jobs, jobrunner.Job{
			CheckID:      c.Id,
			StartTime:    time.Now(),
			Image:        ch.Image,
			Target:       c.NewTarget,
			Timeout:      timeout,
			Options:      ops,
			AssetType:    c.AssetType,
			RequiredVars: vars,
		})
	}
	return jobs, nil
}

func stringInSlice(a string, list []string) bool {
	for _, b := range list {
		if b == a {
			return true
		}
	}
	return false
}

// getTypesFromIdentifier infers the AssetType from an asset identifier
// This code is borrowed from https://github.com/adevinta/vulcan-api/blob/master/pkg/api/service/assets.go#L598
// could be moved to vulcan-types in order to allow reuse.
func getTypesFromIdentifier(target config.Target) ([]config.Target, error) {
	identifier := target.Target
	a := config.Target{
		Target:  identifier,
		Options: target.Options,
	}

	if types.IsAWSARN(identifier) {
		a.AssetType = "AWSAccount"
		return []config.Target{a}, nil
	}

	if types.IsDockerImage(identifier) {
		a.AssetType = "DockerImage"
		return []config.Target{a}, nil
	}

	if types.IsGitRepository(identifier) {
		a.AssetType = "GitRepository"
		return []config.Target{a}, nil
	}

	if _, err := GetValidGitDirectory(identifier); err == nil {
		a.AssetType = "GitRepository"
		return []config.Target{a}, nil
	}

	if types.IsIP(identifier) {
		a.AssetType = "IP"
		return []config.Target{a}, nil
	}

	if types.IsCIDR(identifier) {
		a.AssetType = "IPRange"

		// In case the CIDR has a /32 mask, remove the mask
		// and add the asset as an IP.
		if types.IsHost(identifier) {
			a.Target = strings.TrimSuffix(identifier, "/32")
			a.AssetType = "IP"
		}

		return []config.Target{a}, nil
	}

	var targets []config.Target

	isWeb := false
	if types.IsURL(identifier) {
		isWeb = true

		// From a URL like https://adevinta.com not only a WebAddress
		// type can be extracted, also a hostname (adevinta.com) and
		// potentially a domain name.
		u, err := url.ParseRequestURI(identifier)
		if err != nil {
			return nil, err
		}
		identifier = u.Hostname() // Overwrite identifier to check for hostname and domain.
	}

	if types.IsHostname(identifier) {
		// Prevent using localhost as a Hostname
		if !regexp.MustCompile(`(?i)(localhost|127.0.0.1)`).MatchString(identifier) {
			h := config.Target{
				Target:    identifier,
				AssetType: "Hostname",
				Options:   target.Options, // Use the same options
			}
			targets = append(targets, h)
		}

		// Add WebAddress type only for URLs with valid hostnames.
		if isWeb {
			// At this point a.Target contains the original identifier,
			// not the overwritten identifier.
			a.AssetType = "WebAddress"
			targets = append(targets, a)
		}
	}

	ok, err := types.IsDomainName(identifier)
	if err != nil {
		return nil, fmt.Errorf("can not guess if the asset is a domain: %v", err)
	}
	if ok {
		d := config.Target{
			Target:    identifier,
			AssetType: "DomainName",
			Options:   target.Options, // Use the same options
		}
		targets = append(targets, d)
	}

	return targets, nil
}

// GenerateChecksFromTargets expands the list of targets by inferring missing AssetTypes
// and generates the list of checks to run based on the available Checktypes and AssetType.
func ComputeTargets(cfg *config.Config, l log.Logger) error {
	// Generate a new list of Targets with AssetType
	expandedTargets := []config.Target{}
	for _, t := range cfg.Targets {
		if t.AssetType == "" {
			// Try to infer the asset type
			if inferredTargets, err := getTypesFromIdentifier(t); err != nil {
				l.Errorf("skipping target %s unable to infer assetType %+v", t.Target, err)
				continue
			} else {
				for _, a := range inferredTargets {
					l.Debugf("Inferred asset type target=%s assetType=%s", a.Target, a.AssetType)
				}
				expandedTargets = append(expandedTargets, inferredTargets...)
			}
		} else {
			expandedTargets = append(expandedTargets, t)
		}
	}

	// Generate checks of unique targets (target + assettype + options)
	uniq := map[string]interface{}{}  // controls duplicates
	dedupTargets := []config.Target{} // new list of unique targets
	for _, a := range expandedTargets {
		f := ComputeFingerprint(a)
		if _, ok := uniq[f]; ok {
			l.Debugf("Skipping duplicated target %v", a)
		} else {
			dedupTargets = append(dedupTargets, a)
			uniq[f] = nil
		}
	}
	cfg.Targets = dedupTargets
	return nil
}

func ComputeFingerprint(args ...interface{}) string {
	h := sha256.New()

	for _, a := range args {
		fmt.Fprintf(h, " - %v", a)
	}

	return fmt.Sprintf("%x", h.Sum(nil))
}

// This function is called if a policy has been set, and creates a list of checks to run based on targets
// and policy.
func AddPolicyChecks(cfg *config.Config, l log.Logger) error {
	policy, err := GetPolicy(cfg)
	if err != nil {
		return err
	}
	l.Infof("Applying policy %s", policy.Name)
	checks := []config.Check{} // Ignore the checks in the configuration file when applying a policy.
	for _, t := range cfg.Targets {
		for _, pct := range policy.CheckTypes {
			// Identify CheckType referenced by policy in CheckTypes definition, log error if it doesn't exist
			// and continue.
			c, ok := cfg.CheckTypes[pct.CheckType]
			if !ok {
				l.Errorf("Check %s from policy %s not found", pct.CheckType, policy.Name)
				continue
			}
			if stringInSlice(t.AssetType, c.Assets) {
				options := mergeOptions(c.Options, pct.Options) // Merge check options with policy options.
				options = mergeOptions(options, t.Options)      // Merge options with target options.
				checks = append(checks, config.Check{
					Type:      pct.CheckType,
					Target:    t.Target,
					AssetType: t.AssetType,
					Options:   options,
				})
			}
		}
	}
	cfg.Checks = append(cfg.Checks, checks...)
	return nil
}

// This function is called if no policy has been set, and creates a list of checks to run based on targets and
// available checks.
func AddAllChecks(cfg *config.Config, l log.Logger) error {
	checks := []config.Check{}
	for _, t := range cfg.Targets {
		for ref, c := range cfg.CheckTypes {
			if stringInSlice(t.AssetType, c.Assets) {
				options := mergeOptions(c.Options, t.Options) // Merge check options with target options.
				checks = append(checks, config.Check{
					Type:      ref,
					Target:    t.Target,
					AssetType: t.AssetType,
					Options:   options,
				})
			}
		}
	}
	cfg.Checks = append(cfg.Checks, checks...)
	return nil
}

func SendJobs(jobs []jobrunner.Job, arn, endpoint string, l log.Logger) error {
	qw, err := sqs.NewWriter(arn, endpoint, l)
	if err != nil {
		l.Errorf("error creating sqs writer %+v", err)
		return err
	}
	for _, job := range jobs {
		bytes, err := json.Marshal(job)
		if err != nil {
			return err
		}
		qw.Write(string(bytes))
	}
	return nil
}

func filterChecktype(name string, include, exclude *regexp.Regexp) bool {
	if include != nil && !include.Match([]byte(name)) {
		return false
	}
	if exclude != nil && exclude.Match([]byte(name)) {
		return false
	}
	return true
}

func ImportRepositories(cfg *config.Config, l log.Logger) error {
	for _, uri := range cfg.Conf.Repositories {
		err := config.AddRepo(cfg, uri, l)
		if err != nil {
			l.Errorf("unable to add repository %s %+v", uri, err)
		}
	}
	return nil
}

func GetValidGitDirectory(path string) (string, error) {
	path, err := GetValidDirectory(path)
	if err != nil {
		return "", err
	}
	_, err = GetValidDirectory(filepath.Join(path, ".git"))
	if err != nil {
		return "", err
	}
	return path, nil
}

func GetValidDirectory(path string) (string, error) {
	path, err := filepath.Abs(path)
	if err != nil {
		return "", fmt.Errorf("could not get absolute path %v", err)
	}
	fileInfo, err := os.Stat(path)
	if err != nil {
		return "", err
	}
	if !fileInfo.IsDir() {
		return "", fmt.Errorf("not a directory %s", path)
	}
	return path, nil
}

func GetPolicy(cfg *config.Config) (config.Policy, error) {
	for _, p := range cfg.Policies {
		if p.Name == cfg.Conf.Policy {
			return p, nil
		}
	}
	return config.Policy{}, fmt.Errorf("Policy %s not found", cfg.Conf.Policy)
}
