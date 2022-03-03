/*
Copyright 2021 Adevinta
*/

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"os"
	"time"

	agentconfig "github.com/adevinta/vulcan-agent/config"
	"github.com/adevinta/vulcan-local/pkg/cmd"
	"github.com/adevinta/vulcan-local/pkg/config"
	"github.com/adevinta/vulcan-local/pkg/reporting"
	"github.com/sirupsen/logrus"
)

const envDefaultChecktypesUri = "VULCAN_CHECKTYPES_URI"

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
			LogLevel:    "info",
			Concurrency: 3,
			IfName:      "docker0",
			Vars:        map[string]string{},
		},
		Reporting: config.Reporting{
			Format: "json",
		},
		CheckTypes: map[config.ChecktypeRef]config.Checktype{},
		Checks:     []config.Check{},
	}

	var help bool
	var configFile, targetOptions string
	cmdTarget := config.Target{}
	flag.BoolVar(&help, "h", false, "print usage")
	flag.StringVar(&configFile, "c", "", "config file (i.e. -c vulcan.yaml)")
	flag.StringVar(&cfg.Conf.LogLevel, "l", cfg.Conf.LogLevel, "log level [panic, fatal, error, warn, info, debug]")
	flag.StringVar(&cfg.Reporting.OutputFile, "r", "", "results file (i.e. -r results.json)")
	flag.StringVar(&cfg.Conf.Include, "i", cfg.Conf.Include, "include checktype regex")
	flag.StringVar(&cfg.Conf.Exclude, "e", cfg.Conf.Exclude, "exclude checktype regex")
	flag.StringVar(&cmdTarget.Target, "t", "", "target to check")
	flag.StringVar(&targetOptions, "o", "", `options related to the target (-t) used in all the their checks (i.e. '{"depth":"1", "max_scan_duration": 1}')`)
	flag.StringVar(&cmdTarget.AssetType, "a", "", "asset type (WebAddress, ...)")
	flag.StringVar(&cfg.Reporting.Threshold, "s", cfg.Reporting.Threshold, fmt.Sprintf("filter by severity %v", reporting.SeverityNames()))
	flag.StringVar(&cfg.Conf.Repository, "u", "", fmt.Sprintf("chektypes uri (or %s)", envDefaultChecktypesUri))
	flag.StringVar(&cfg.Conf.DockerBin, cfg.Conf.DockerBin, cfg.Conf.DockerBin, "docker binary")
	flag.StringVar(&cfg.Conf.GitBin, cfg.Conf.GitBin, cfg.Conf.GitBin, "git binary")
	flag.StringVar(&cfg.Conf.IfName, "ifname", cfg.Conf.IfName, "network interface where agent will be available for the checks")
	flag.IntVar(&cfg.Conf.Concurrency, "concurrency", cfg.Conf.Concurrency, "max number of checks/containers to run concurrently")
	flag.Func("pullpolicy", fmt.Sprintf("when to pull for check images %s", agentconfig.PullPolicies()), func(s string) error {
		return cfg.Conf.PullPolicy.UnmarshalText([]byte(s))
	})
	flag.Parse()

	if help {
		flag.Usage()
		return
	}

	if cfg.Conf.Repository == "" {
		if repo := os.Getenv(envDefaultChecktypesUri); repo != "" {
			cfg.Conf.Repository = repo
		}
	}

	if configFile != "" {
		err = config.ReadConfig(configFile, cfg, log)
		if err != nil {
			log.Errorf("Unable to parse config file %s %+v", configFile, err)
			return
		}
		// Overwrite the yaml config with the command line flags.
		flag.Parse()
	}

	if cmdTarget.Target != "" {
		if targetOptions != "" {
			if err = json.Unmarshal([]byte(targetOptions), &cmdTarget.Options); err != nil {
				log.Errorf("unable to parse options %+v", err)
				return
			}
		}
		cfg.Targets = append(cfg.Targets, cmdTarget)
	} else {
		if targetOptions != "" {
			log.Errorf("Options without target are not allowed")
			return
		}
	}
	exitCode, err = cmd.Run(cfg, log)
	if err != nil {
		log.Print(err)
	}
	os.Exit(exitCode)
}
