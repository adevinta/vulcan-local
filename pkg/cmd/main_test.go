/*
Copyright 2022 Adevinta
*/

package cmd

import (
	"bytes"
	"fmt"
	"os"
	"os/exec"
	"strings"
	"testing"
	"time"

	agentlog "github.com/adevinta/vulcan-agent/log"
	"github.com/adevinta/vulcan-local/pkg/checktypes"
	"github.com/adevinta/vulcan-local/pkg/config"
	"github.com/google/go-cmp/cmp"
	"github.com/sirupsen/logrus"
)

var (
	loggerUser *logrus.Logger
)

func init() {
	if len(os.Args) > 1 && os.Args[1][:5] == "-test" {
		loggerUser = logrus.New()
		loggerUser.SetFormatter(&logrus.TextFormatter{
			DisableColors:   false,
			FullTimestamp:   true,
			TimestampFormat: time.RFC3339,
			ForceColors:     true,
		})
	}
}

type TestCommandRunner struct{}

// newExecCase returns a function for creating a command to execute the current test binary
func newExecCase(test, state string) func(command string, args ...string) *exec.Cmd {
	return func(command string, args ...string) *exec.Cmd {
		cs := []string{"-test.run=" + test, "--", state, command}
		cs = append(cs, args...)
		cmd := exec.Command(os.Args[0], cs...)
		cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}
		return cmd
	}
}

func TestHelperProcess(*testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	defer os.Exit(0)

	args := []string{}
	for i := range os.Args {
		if os.Args[i] == "--" {
			args = os.Args[i+1:]
			break
		}
	}
	// First argument is case and second the exec name.
	if len(args) < 2 {
		os.Exit(1)
	}
	cases := map[string]map[string]struct {
		out  string
		err  string
		exit int
	}{
		"docker-git": {
			"git":    {exit: 0, out: "version fake"},
			"docker": {exit: 0},
		},
		"no-docker": {
			"git":    {exit: 0},
			"docker": {exit: 1},
		},
		"no-git": {
			"git":    {exit: 1},
			"docker": {exit: 0},
		},
		"other-git": {
			"othergit": {exit: 0},
			"docker":   {exit: 0},
		},
	}
	c := args[0]
	uc, ok := cases[c]
	if !ok {
		os.Exit(1)
	}
	exe, ok := uc[args[1]]
	if !ok {
		os.Exit(1)
	}
	if exe.out != "" {
		fmt.Fprintln(os.Stdout, exe.out)
	}
	if exe.err != "" {
		fmt.Fprintln(os.Stderr, exe.err)
	}
	os.Exit(exe.exit)
}

func TestCheckDependencies(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.Config
		state   string
		wantErr string
	}{
		{
			name: "HappyPath",
			cfg: &config.Config{
				Conf: config.Conf{
					DockerBin:   "docker",
					GitBin:      "git",
					LogLevel:    logrus.InfoLevel,
					Concurrency: 3,
					IfName:      "docker0",
					Vars:        map[string]string{},
				},
			},
			state:   "docker-git",
			wantErr: "",
		},
		{
			name: "no-docker",
			cfg: &config.Config{
				Conf: config.Conf{
					DockerBin:   "docker",
					GitBin:      "git",
					LogLevel:    logrus.InfoLevel,
					Concurrency: 3,
					IfName:      "docker0",
					Vars:        map[string]string{},
				},
			},
			state:   "no-docker",
			wantErr: "docker",
		},
		{
			name: "no-git",
			cfg: &config.Config{
				Conf: config.Conf{
					DockerBin:   "docker",
					GitBin:      "git",
					LogLevel:    logrus.InfoLevel,
					Concurrency: 3,
					IfName:      "docker0",
					Vars:        map[string]string{},
				},
			},
			state:   "no-git",
			wantErr: "git",
		},
		{
			name: "other-git-missing",
			cfg: &config.Config{
				Conf: config.Conf{
					DockerBin:   "docker",
					GitBin:      "othergit",
					LogLevel:    logrus.InfoLevel,
					Concurrency: 3,
					IfName:      "docker0",
					Vars:        map[string]string{},
				},
			},
			state:   "docker-git",
			wantErr: "git",
		},
		{
			name: "other-git-ok",
			cfg: &config.Config{
				Conf: config.Conf{
					DockerBin:   "docker",
					GitBin:      "othergit",
					LogLevel:    logrus.InfoLevel,
					Concurrency: 3,
					IfName:      "docker0",
					Vars:        map[string]string{},
				},
			},
			state:   "other-git",
			wantErr: "",
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			execCommand = newExecCase("TestHelperProcess", tt.state)
			err := checkDependencies(tt.cfg, loggerUser)
			if err == nil {
				if tt.wantErr != "" {
					t.Errorf("Wanted error")
				}
			} else {
				if tt.wantErr == "" {
					t.Errorf("Unexpected error")
				} else {
					if !strings.Contains(err.Error(), tt.wantErr) {
						t.Errorf("Unexpected error type")
					}
				}
			}
		})
	}

}

func TestCheckRequiredVariables(t *testing.T) {

	buf := bytes.Buffer{}
	loggerUser.SetOutput(&buf)

	defer func() {
		loggerUser.SetOutput(os.Stderr)
	}()

	tests := []struct {
		name    string
		cfg     *config.Config
		want    []string
		wantErr error
	}{
		{
			name: "HappyPath",
			cfg: &config.Config{
				Conf: config.Conf{
					Vars: map[string]string{
						"A": "a",
						"B": "b",
						"C": "c",
					},
				},
				Checks: []config.Check{
					{
						Checktype: &checktypes.Checktype{
							RequiredVars: []string{"A", "B", "C"},
						},
					},
				},
			},
			want:    []string{""},
			wantErr: nil,
		},
		{
			name: "Missing one Variable",
			cfg: &config.Config{
				Conf: config.Conf{
					LogLevel: logrus.InfoLevel,
					Vars: map[string]string{
						"A": "a",
						"B": "b",
					},
				},
				Checks: []config.Check{
					{
						Checktype: &checktypes.Checktype{
							RequiredVars: []string{"A", "B", "C"},
						},
					},
				},
			},
			want:    []string{"Missing required variable C for the check"},
			wantErr: nil,
		},
		{
			name: "Missing two Variable",
			cfg: &config.Config{
				Conf: config.Conf{
					LogLevel: logrus.InfoLevel,
					Vars: map[string]string{
						"A": "a",
					},
				},
				Checks: []config.Check{
					{
						Checktype: &checktypes.Checktype{
							RequiredVars: []string{"A", "B", "C"},
						},
					},
				},
			},
			want: []string{
				"Missing required variable B for the check",
				"Missing required variable C for the check"},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			loggerUser.SetLevel(agentlog.ParseLogLevel(tt.cfg.Conf.LogLevel.String()))

			checkRequiredVariables(tt.cfg, loggerUser)
			got := buf.String()
			for _, want := range tt.want {
				if !strings.Contains(got, want) {
					t.Errorf("Wanted %s, got %s", tt.want, got)
				}
			}
			buf.Reset()
		})
	}
}

func TestUpsertEnv(t *testing.T) {
	tests := []struct {
		name     string
		envs     []string
		varName  string
		newValue string
		want     []string
	}{
		{
			name: "HappyPath",
			envs: []string{
				"a=a", "b=b",
			},
			varName:  "a",
			newValue: "c",
			want: []string{
				"a=c", "b=b",
			},
		},
		{
			name:     "Insert variable",
			envs:     []string{},
			varName:  "a",
			newValue: "c",
			want: []string{
				"a=c",
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := upsertEnv(tt.envs, tt.varName, tt.newValue)
			diff := cmp.Diff(tt.want, got)
			if diff != "" {
				t.Errorf("%v\n", diff)
			}
		})
	}

}
