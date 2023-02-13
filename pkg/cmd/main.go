/*
Copyright 2021 Adevinta
*/

package cmd

import (
	"bytes"
	"fmt"
	"net"
	"os"
	"os/exec"
	"regexp"
	"runtime"
	"strconv"
	"strings"
	"time"

	"github.com/adevinta/vulcan-agent/agent"
	"github.com/adevinta/vulcan-agent/backend"
	"github.com/adevinta/vulcan-agent/backend/docker"
	agentconfig "github.com/adevinta/vulcan-agent/config"
	agentlog "github.com/adevinta/vulcan-agent/log"
	"github.com/adevinta/vulcan-local/pkg/checktypes"
	"github.com/adevinta/vulcan-local/pkg/config"
	"github.com/adevinta/vulcan-local/pkg/generator"
	"github.com/adevinta/vulcan-local/pkg/gitservice"
	"github.com/adevinta/vulcan-local/pkg/reporting"
	"github.com/adevinta/vulcan-local/pkg/results"
	"github.com/adevinta/vulcan-local/pkg/sqsservice"
	"github.com/sirupsen/logrus"
)

const defaultDockerHost = "host.docker.internal"

var execCommand = exec.Command

func GetFreePort() (int, error) {
	addr, err := net.ResolveTCPAddr("tcp", ":0")
	if err != nil {
		return 0, err
	}
	l, err := net.ListenTCP("tcp", addr)
	if err != nil {
		return 0, err
	}
	defer l.Close()
	return l.Addr().(*net.TCPAddr).Port, nil
}

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

	agentIP := getAgentIP(cfg.Conf.IfName, log)
	if agentIP == "" {
		return config.ErrorExitCode, fmt.Errorf("unable to get the agent ip %s", cfg.Conf.IfName)
	}

	hostIP := getHostIP(log)
	if hostIP == "" {
		return config.ErrorExitCode, fmt.Errorf("unable to infer host ip")
	}

	gs := gitservice.New(log)
	defer gs.Shutdown()
	log.Debug("Generating jobs")
	jobs, err := generator.GenerateJobs(cfg, agentIP, hostIP, gs, log)
	if err != nil {
		return config.ErrorExitCode, fmt.Errorf("unable to generate checks %+v", err)
	}

	if len(jobs) == 0 {
		log.Infof("Empty list of checks")
		return config.SuccessExitCode, nil
	}

	// AWS Credentials are required for sqs
	os.Setenv("AWS_REGION", "local")
	os.Setenv("AWS_SECRET_ACCESS_KEY", "TBD")
	os.Setenv("AWS_ACCESS_KEY_ID", "TBD")

	sqs, err := sqsservice.Start(log)
	if err != nil {
		return config.ErrorExitCode, fmt.Errorf("unable to parse start sqs server %w", err)
	}
	defer sqs.Shutdown()

	results, err := results.Start(log)
	if err != nil {
		return config.ErrorExitCode, fmt.Errorf("unable to start results server %+v", err)
	}
	defer results.Shutdown()
	log.Debug("Sending jobs to run")
	err = generator.SendJobs(jobs, sqs.ArnChecks, sqs.Endpoint, log)
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

	agentPort, err := GetFreePort()
	if err != nil {
		return config.ErrorExitCode, fmt.Errorf("unable to get a free port for agent %+v", err)
	}
	agentConfig := agentconfig.Config{
		Agent: agentconfig.AgentConfig{
			ConcurrentJobs:         cfg.Conf.Concurrency,
			MaxNoMsgsInterval:      5, // Low as all the messages will be in the queue before starting the agent.
			MaxProcessMessageTimes: 1, // No retry
			Timeout:                180,
		},
		SQSReader: agentconfig.SQSReader{
			Endpoint:          sqs.Endpoint,
			ARN:               sqs.ArnChecks,
			PollingInterval:   3,
			VisibilityTimeout: 120,
		},
		SQSWriter: agentconfig.SQSWriter{
			Endpoint: sqs.Endpoint,
			ARN:      sqs.ArnStatus,
		},
		Uploader: agentconfig.UploaderConfig{
			Endpoint: results.Endpoint,
		},
		API: agentconfig.APIConfig{
			Host: agentIP,
			Port: fmt.Sprintf(":%d", agentPort),
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
	beforeRun := func(params backend.RunParams, rc *docker.RunConfig) error {
		return beforeCheckRun(params, rc, agentIP, gs, hostIP, cfg.Checks, log)
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
	exit := agent.Run(agentConfig, backend, logAgent.WithField("comp", "agent"))
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

func GetInterfaceAddr(ifaceName string) (string, error) {
	iface, err := net.InterfaceByName(ifaceName)
	if err != nil {
		return "", err
	}
	addrs, err := iface.Addrs()
	if err != nil {
		return "", err
	}

	for _, addr := range addrs {
		ip, _, err := net.ParseCIDR(addr.String())
		if err != nil {
			return "", err
		}

		// Check if it is IPv4.
		if ip.To4() != nil {
			return ip.To4().String(), nil
		}
	}

	return "", fmt.Errorf("failed to determine Docker agent IP address")
}

func getAgentIP(ifacename string, log agentlog.Logger) string {
	ip, err := GetInterfaceAddr(ifacename)
	if err == nil {
		log.Debugf("Agent address iface=%s ip=%s", ifacename, ip)
		return ip
	}

	os := runtime.GOOS
	switch os {
	case "darwin":
		log.Debugf("Agent address os=%s ip=%s", os, defaultDockerHost)
		return defaultDockerHost
	case "linux":
		// Perhaps the agent is running in a container...
		ip, err = GetInterfaceAddr("eth0")
		if err == nil {
			log.Debugf("Agent address iface=eth0 os=%s ip=%s", os, ip)
			return ip
		}
	}
	log.Errorf("Unable to get agent address iface=%s os=%s", ifacename, os)
	return ""
}

func getHostIP(l agentlog.Logger) string {
	cmd := exec.Command("docker", "run", "--rm", "busybox:1.34.1", "sh", "-c", "ip route|awk '/default/ { print $3 }'")
	var cmdOut bytes.Buffer
	cmd.Stdout = &cmdOut
	err := cmd.Run()
	if err != nil {
		l.Errorf("unable to get Hostip %v %v", err, cmdOut.String())
		return ""
	}
	ip := strings.TrimSuffix(cmdOut.String(), "\n")
	l.Debugf("Hostip=%s", ip)
	return ip
}

// beforeCheckRun is a hook executed by the agent just before a check is run
// in. it's used to do some extra configuration needed for some checks to run
// properly when they are executed locally.
func beforeCheckRun(params backend.RunParams, rc *docker.RunConfig,
	agentIP string, gs gitservice.GitService, hostIP string,
	checks []config.Check, log *logrus.Logger) error {
	newTarget := params.Target
	// If the asset type is a DockerImage mount the docker socket in case the image is already there,
	// and the check can access it.
	if params.AssetType == "DockerImage" {
		rc.HostConfig.Binds = append(rc.HostConfig.Binds, "/var/run/docker.sock:/var/run/docker.sock")

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
			newTarget = fmt.Sprintf("http://%s:%d/", agentIP, port)
		}

	}

	newTarget = regexp.MustCompile(`(?i)\b(localhost|127.0.0.1)\b`).ReplaceAllString(newTarget, hostIP)

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
