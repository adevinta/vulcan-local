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

func (r TestCommandRunner) Run(command string, dependencyName string, args ...string) error {

	cs := []string{"-test.run=TestHelperProcess", "--"}
	cs = append(cs, args...)
	cmd := exec.Command(os.Args[0], cs...)
	cmd.Env = []string{"GO_WANT_HELPER_PROCESS=1"}
	err := cmd.Run()
	return err
}

func TestHelperProcess(*testing.T) {
	if os.Getenv("GO_WANT_HELPER_PROCESS") != "1" {
		return
	}
	defer os.Exit(0)
	fmt.Println("testing helper process")
}

func TestCheckDependencies(t *testing.T) {
	commandRunner = TestCommandRunner{}

	tests := []struct {
		name    string
		cfg     *config.Config
		want    interface{}
		wantErr error
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
			want:    nil,
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			err := checkDependencies(tt.cfg, loggerUser)
			if err != tt.wantErr {
				t.Errorf("Unexcepcted error")
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
						Checktype: &config.Checktype{
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
						Checktype: &config.Checktype{
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
						Checktype: &config.Checktype{
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
		wantErr  error
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
			wantErr: nil,
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
