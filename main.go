/*
Copyright 2021 Adevinta
*/

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"runtime"
	"runtime/debug"
	"time"

	agentconfig "github.com/adevinta/vulcan-agent/config"
	"github.com/adevinta/vulcan-local/pkg/cmd"
	"github.com/adevinta/vulcan-local/pkg/config"
	"github.com/sirupsen/logrus"
)

const envDefaultChecktypesUri = "VULCAN_CHECKTYPES_URI"
const envDefaultVulcanLocalUri = "VULCAN_LOCAL_CONFIG"

var (
	version = "dev"
	commit  = ""
	date    = ""
	builtBy = ""
)

func main() {
	exitCode := 1
	defer os.Exit(exitCode)

	var err error

	log := logrus.New()
	log.SetFormatter(&logrus.TextFormatter{
		DisableColors:   false,
		FullTimestamp:   true,
		TimestampFormat: time.RFC3339,
		ForceColors:     true,
	})

	cfg := &config.Config{
		Conf: config.Conf{
			DockerBin:   "docker",
			GitBin:      "git",
			LogLevel:    logrus.InfoLevel,
			Concurrency: 3,
			IfName:      "docker0",
			Vars:        map[string]string{},
		},
		Reporting: config.Reporting{
			Format:   "json",
			Severity: config.SeverityHigh,
		},
		CheckTypes: map[config.ChecktypeRef]config.Checktype{},
		Checks:     []config.Check{},
	}

	cmdTargets := []*config.Target{}
	cmdRepositories := []string{}
	cmdConfigs := []string{}

	var showHelp, showVersion bool
	flag.BoolVar(&showHelp, "h", false, "print usage")
	flag.BoolVar(&showVersion, "version", false, "print version")
	flag.Func("c", fmt.Sprintf("config file (i.e. -c vulcan.yaml). Can be used multiple times. (Also env %s)", envDefaultVulcanLocalUri), func(s string) error {
		cmdConfigs = append(cmdConfigs, s)
		return nil
	})
	flag.Func("l", fmt.Sprintf("log level %v (default %s)", logrus.AllLevels, cfg.Conf.LogLevel.String()), func(s string) error {
		return cfg.Conf.LogLevel.UnmarshalText([]byte(s))
	})
	flag.StringVar(&cfg.Conf.Policy, "p", "", "policy to execute")
	flag.StringVar(&cfg.Reporting.OutputFile, "r", "", "results file (i.e. -r results.json)")
	flag.StringVar(&cfg.Conf.Include, "i", cfg.Conf.Include, "include checktype regex")
	flag.StringVar(&cfg.Conf.Exclude, "e", cfg.Conf.Exclude, "exclude checktype regex")
	flag.Func("t", "target to scan. Can be used multiple times.", func(s string) error {
		cmdTargets = append(cmdTargets, &config.Target{
			Target: s,
		})
		return nil
	})
	flag.Func("a", "asset type of the last target (-t)", func(s string) error {
		if len(cmdTargets) == 0 {
			return fmt.Errorf("missing target")
		}
		lastTarget := cmdTargets[len(cmdTargets)-1]
		if lastTarget.AssetType != "" {
			return fmt.Errorf("asset type already defined for %s", lastTarget.Target)
		}
		lastTarget.AssetType = s
		return nil
	})
	flag.Func("o", `options related to the last target (-t) used in all the their checks (i.e. '{"depth":"1", "max_scan_duration": 1}')`, func(s string) error {
		if len(cmdTargets) == 0 {
			return fmt.Errorf("missing target")
		}
		lastTarget := cmdTargets[len(cmdTargets)-1]
		if lastTarget.Options != nil {
			return fmt.Errorf("options already defined for target %s", lastTarget.Target)
		}
		if err := json.Unmarshal([]byte(s), &lastTarget.Options); err != nil {
			return fmt.Errorf("unable to parse options %v", err)
		}
		return nil
	})
	flag.Func("s", fmt.Sprintf("filter by severity %v (default %s)", config.SeverityNames(), cfg.Reporting.Severity.Data().Name), func(s string) error {
		return cfg.Reporting.Severity.UnmarshalText([]byte(s))
	})
	flag.Func("u", fmt.Sprintf("checktype uris. Can be used multiple times. (Also env %s)", envDefaultChecktypesUri), func(s string) error {
		cmdRepositories = append(cmdRepositories, s)
		return nil
	})
	flag.StringVar(&cfg.Conf.DockerBin, cfg.Conf.DockerBin, cfg.Conf.DockerBin, "docker binary")
	flag.StringVar(&cfg.Conf.GitBin, cfg.Conf.GitBin, cfg.Conf.GitBin, "git binary")
	flag.StringVar(&cfg.Conf.IfName, "ifname", cfg.Conf.IfName, "network interface where agent will be available for the checks")
	flag.IntVar(&cfg.Conf.Concurrency, "concurrency", cfg.Conf.Concurrency, "max number of checks/containers to run concurrently")
	flag.Func("pullpolicy", fmt.Sprintf("when to pull for check images %s", agentconfig.PullPolicies()), func(s string) error {
		return cfg.Conf.PullPolicy.UnmarshalText([]byte(s))
	})
	flag.Parse()

	log.SetLevel(cfg.Conf.LogLevel)

	if showHelp {
		flag.Usage()
		return
	}

	if showVersion {
		result := fmt.Sprintf("vulcan-local version: %s", version)
		if commit != "" {
			result = fmt.Sprintf("%s\ncommit: %s", result, commit)
		}
		if date != "" {
			result = fmt.Sprintf("%s\nbuilt at: %s", result, date)
		}
		if builtBy != "" {
			result = fmt.Sprintf("%s\nbuilt by: %s", result, builtBy)
		}
		result = fmt.Sprintf("%s\ngoos: %s\ngoarch: %s", result, runtime.GOOS, runtime.GOARCH)
		if info, ok := debug.ReadBuildInfo(); ok && info.Main.Sum != "" {
			result = fmt.Sprintf("%s\nmodule version: %s, checksum: %s", result, info.Main.Version, info.Main.Sum)
		}
		fmt.Print(result)
		fmt.Print("\n")
		return
	}

	if env := os.Getenv(envDefaultVulcanLocalUri); env != "" {
		log.Debugf("Adding config from %s uri=%s", envDefaultVulcanLocalUri, env)
		cmdConfigs = append(cmdConfigs, env)
	}
	if len(cmdConfigs) > 0 {
		for _, uri := range cmdConfigs {
			err = config.ReadConfig(uri, cfg, log)
			if err != nil {
				log.Errorf("Unable to parse config file %s %+v", uri, err)
				return
			}
		}
		// Overwrite the yaml config with the command line flags.
		flag.Parse()
	}

	if repo := os.Getenv(envDefaultChecktypesUri); repo != "" {
		log.Debugf("Adding config from %s uri=%s", envDefaultChecktypesUri, repo)
		cfg.Conf.Repositories = append(cfg.Conf.Repositories, repo)
	}
	cfg.Conf.Repositories = append(cfg.Conf.Repositories, cmdRepositories...)

	// Overwrite config targets in case of command line targets
	if len(cmdTargets) > 0 {
		cfg.Targets = []config.Target{}
		for i := range cmdTargets {
			cfg.Targets = append(cfg.Targets, *cmdTargets[i])
		}
	}

	exitCode, err = cmd.Run(cfg, log)
	if err != nil {
		log.Error(err)
	}
	os.Exit(exitCode)
}
