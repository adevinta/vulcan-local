/*
Copyright 2021 Adevinta
*/

package cmd

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"os/exec"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/adevinta/vulcan-agent/agent"
	"github.com/adevinta/vulcan-agent/backend"
	"github.com/adevinta/vulcan-agent/backend/docker"
	agentconfig "github.com/adevinta/vulcan-agent/config"
	agentlog "github.com/adevinta/vulcan-agent/log"
	"github.com/adevinta/vulcan-agent/queue"
	"github.com/adevinta/vulcan-agent/queue/chanqueue"
	"github.com/docker/docker/client"
	"github.com/sirupsen/logrus"

	"github.com/adevinta/vulcan-local/pkg/checktypes"
	"github.com/adevinta/vulcan-local/pkg/config"
	"github.com/adevinta/vulcan-local/pkg/dockerutil"
	"github.com/adevinta/vulcan-local/pkg/generator"
	"github.com/adevinta/vulcan-local/pkg/gitservice"
	"github.com/adevinta/vulcan-local/pkg/reporting"
	"github.com/adevinta/vulcan-local/pkg/results"
)

const dockerHostname = "host.docker.internal"

var (
	localRegex  = regexp.MustCompile(`(?i)\b(localhost|127.0.0.1)\b`)
	dockerHost  = ""
	execCommand = exec.Command
)

func Run(cfg *config.Config, log *logrus.Logger) (int, error) {
	var err error

	log.SetLevel(agentlog.ParseLogLevel(cfg.Conf.LogLevel.String()))

	if err = checkDependencies(cfg, log); err != nil {
		return config.ErrorExitCode, fmt.Errorf("unmet dependencies: %w", err)
	}

	if cfg.Conf.Include != "" {
		if cfg.Conf.IncludeR, err = regexp.Compile(cfg.Conf.Include); err != nil {
			return config.ErrorExitCode, fmt.Errorf("invalid include regexp: %w", err)
		}
	}
	if cfg.Conf.Exclude != "" {
		if cfg.Conf.ExcludeR, err = regexp.Compile(cfg.Conf.Exclude); err != nil {
			return config.ErrorExitCode, fmt.Errorf("invalid exclude regexp: %w", err)
		}
	}
	checktypes, err := checktypes.Import(cfg.Conf.Repositories, log)
	if err != nil {
		return config.ErrorExitCode, fmt.Errorf("unable to load repositories: %w", err)
	}
	cfg.CheckTypes = checktypes
	if err = generator.ComputeTargets(cfg, log); err != nil {
		return config.ErrorExitCode, err
	}

	// If a policy is set, apply it on all the targets and ignore the checks set before, otherwise
	// run all available checks against all the targets.
	if cfg.Conf.Policy != "" {
		cfg.Checks = []config.Check{} // Remove existing checks before applying the policy.
		log.Debug("Adding policy checks")
		if err := generator.AddPolicyChecks(cfg, log); err != nil {
			return config.ErrorExitCode, err
		}
	} else {
		log.Debug("Adding all checks")
		if err := generator.AddAllChecks(cfg, log); err != nil {
			return config.ErrorExitCode, err
		}
	}

	cli, err := client.NewClientWithOpts(client.FromEnv, client.WithAPIVersionNegotiation())
	if err != nil {
		return config.ErrorExitCode, fmt.Errorf("unable to get docker client: %v", err)
	}
	dockerHost = cli.DaemonHost()
	log.Debugf("Using docker host=%s", dockerHost)

	log.Debug("Generating jobs")
	jobs, err := generator.GenerateJobs(cfg, log)
	if err != nil {
		return config.ErrorExitCode, fmt.Errorf("unable to generate checks %+v", err)
	}

	if len(jobs) == 0 {
		log.Infof("Empty list of checks")
		return config.SuccessExitCode, nil
	}

	results, err := results.Start(log)
	if err != nil {
		return config.ErrorExitCode, fmt.Errorf("unable to start results server %+v", err)
	}

	log.Debug("Sending jobs to run")
	jobsQueue := chanqueue.New(nil)
	err = generator.SendJobs(jobs, jobsQueue, log)
	if err != nil {
		return config.ErrorExitCode, fmt.Errorf("unable to send jobs to queue %+v", err)
	}

	auths := []agentconfig.Auth{}
	for _, r := range cfg.Conf.Registries {
		if r.Server == "" || r.Username == "" || r.Password == "" {
			log.Debugf("Skipping empty registry")
			continue
		}
		auths = append(auths, agentconfig.Auth{
			Server: r.Server,
			User:   r.Username,
			Pass:   r.Password,
		})
	}

	listenHost, err := dockerutil.GetBridgeHost(cli)
	if err != nil {
		return config.ErrorExitCode, fmt.Errorf("could not get listen addr: %w", err)
	}
	listenAddr := listenHost + ":0"
	ln, err := net.Listen("tcp", listenAddr)
	if err != nil {
		return config.ErrorExitCode, fmt.Errorf("unable to listen on %v: %w", listenAddr, err)
	}

	agentConfig := agentconfig.Config{
		Agent: agentconfig.AgentConfig{
			ConcurrentJobs:         cfg.Conf.Concurrency,
			MaxNoMsgsInterval:      5, // Low as all the messages will be in the queue before starting the agent.
			MaxProcessMessageTimes: 1, // No retry
			Timeout:                180,
		},
		API: agentconfig.APIConfig{
			Host:     dockerHostname,
			Listener: ln,
		},
		Check: agentconfig.CheckConfig{
			Vars: cfg.Conf.Vars,
		},
		Runtime: agentconfig.RuntimeConfig{
			Docker: agentconfig.DockerConfig{
				Registry: agentconfig.RegistryConfig{
					PullPolicy:          cfg.Conf.PullPolicy,
					BackoffMaxRetries:   5,
					BackoffInterval:     5,
					BackoffJitterFactor: 0.5,
					Auths:               auths,
				},
			},
		},
	}

	gs := gitservice.New(listenHost, log)
	defer gs.Shutdown()

	beforeRun := func(params backend.RunParams, rc *docker.RunConfig) error {
		return beforeCheckRun(params, rc, gs, cfg.Checks, log)
	}
	backend, err := docker.NewBackend(log, agentConfig, beforeRun)
	if err != nil {
		return config.ErrorExitCode, err
	}

	// Show progress to prevent CI/CD complaining of no output for long time.
	quitProgress := make(chan bool)
	go func() {
		for {
			select {
			case <-quitProgress:
				return
			case <-time.After(30 * time.Second):
				reporting.ShowProgress(cfg, results, log)
			}
		}
	}()

	logAgent := log
	// Mute the agent to Error except if in Debug mode.
	if log.Level != logrus.DebugLevel {
		logAgent = logrus.New()
		logAgent.SetFormatter(log.Formatter)
		logAgent.SetLevel(logrus.ErrorLevel)
	}

	// Create a state queue and discard all messages.
	stateQueue := chanqueue.New(queue.Discard())
	stateQueue.StartReading(context.Background())

	exit := agent.RunWithQueues(agentConfig, results, backend, stateQueue, jobsQueue, logAgent.WithField("comp", "agent"))
	if exit != 0 {
		return config.ErrorExitCode, fmt.Errorf("error running the agent exit=%d", exit)
	}

	quitProgress <- true

	reporting.ShowProgress(cfg, results, log)
	reporting.ShowSummary(cfg, results, log)
	reportCode, err := reporting.Generate(cfg, results, log)
	if err != nil {
		return config.ErrorExitCode, fmt.Errorf("error generating report %+v", err)
	}

	return reportCode, nil
}

func upsertEnv(envs []string, name, newValue string) []string {
	for i, e := range envs {
		if strings.HasPrefix(e, name+"=") {
			envs[i] = fmt.Sprintf("%s=%s", name, newValue)
			return envs
		}
	}
	return append(envs, fmt.Sprintf("%s=%s", name, newValue))
}

// checkDependencies checks that all the dependencies are present and run
// normally.
func checkDependencies(cfg *config.Config, log agentlog.Logger) error {
	var cmdOut bytes.Buffer

	log.Debugf("Checking dependency docker=%s", cfg.Conf.DockerBin)
	cmd := execCommand(cfg.Conf.DockerBin, "ps", "-q")
	cmd.Stderr = &cmdOut
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("checking docker dependency bin=%s %w %s", cfg.Conf.DockerBin, err, cmdOut.String())
	}

	log.Debugf("Checking dependency git=%s", cfg.Conf.GitBin)
	cmd = execCommand(cfg.Conf.GitBin, "version")
	cmd.Stderr = &cmdOut
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("checking git dependency bin=%s %w %s", cfg.Conf.GitBin, err, cmdOut.String())
	}
	return nil
}

// beforeCheckRun is a hook executed by the agent just before a check is run
// in. it's used to do some extra configuration needed for some checks to run
// properly when they are executed locally.
func beforeCheckRun(params backend.RunParams, rc *docker.RunConfig, gs gitservice.GitService,
	checks []config.Check, log *logrus.Logger) error {
	rc.HostConfig.ExtraHosts = []string{dockerHostname + ":host-gateway"}

	newTarget := params.Target
	// If the asset type is a DockerImage mount the docker socket in case the image is already there,
	// and the check can access it.
	if params.AssetType == "DockerImage" {

		if strings.HasPrefix(dockerHost, "unix://") {
			dockerVol := strings.TrimPrefix(dockerHost, "unix://")
			// Mount the volume in the standard location.
			rc.HostConfig.Binds = append(rc.HostConfig.Binds, fmt.Sprintf("%s:/var/run/docker.sock", dockerVol))
		} else {
			// for ssh / http / https just set DOCKER_HOST replacing localhost with the docker host hostname.
			h := localRegex.ReplaceAllString(dockerHost, dockerHostname)
			rc.ContainerConfig.Env = upsertEnv(rc.ContainerConfig.Env, "DOCKER_HOST", h)
		}

		// Some checks will fail because the reachability check as they
		// expect remote urls. This will bypass the check
		// (https://github.com/adevinta/vulcan-check-sdk/blob/master/helpers/target.go#L294)
		// TODO: Find a propper way to do this either by updating
		// IsDockerImgReachable or custom whitelisting in the check.
		rc.ContainerConfig.Env = upsertEnv(rc.ContainerConfig.Env, backend.CheckAssetTypeVar, "LocalDockerImage")
	} else if params.AssetType == "GitRepository" {

		if path, err := generator.GetValidDirectory(params.Target); err == nil {
			port, err := gs.AddGit(path)
			if err != nil {
				log.Errorf("Unable to create local git server check %v", err)
				return nil
			}
			newTarget = fmt.Sprintf("http://%s:%d/", dockerHostname, port)
		}

	}

	newTarget = localRegex.ReplaceAllString(newTarget, dockerHostname)

	if params.Target != newTarget {
		check := getCheckByID(checks, params.CheckID)
		if check == nil {
			log.Errorf("check not found id=%s", params.CheckID)
			return nil
		}

		log.Debugf("swaping target=%s new=%s check=%s", params.Target, newTarget, params.CheckID)
		check.NewTarget = newTarget
		rc.ContainerConfig.Env = upsertEnv(rc.ContainerConfig.Env, backend.CheckTargetVar, newTarget)
	}

	// We allow all the checks to scan local assets. This could be tunned
	// depending on the target/assettype.
	rc.ContainerConfig.Env = upsertEnv(rc.ContainerConfig.Env, "VULCAN_ALLOW_PRIVATE_IPS", strconv.FormatBool(true))

	return nil
}

func getCheckByID(checks []config.Check, id string) *config.Check {
	for i, c := range checks {
		if c.Id == id {
			return &checks[i]
		}
	}
	return nil
}
