/*
Copyright 2022 Adevinta
*/
package reporting

import (
	"bytes"
	"os"
	"strings"
	"testing"
	"time"

	agentlog "github.com/adevinta/vulcan-agent/log"
	"github.com/adevinta/vulcan-local/pkg/checktypes"
	"github.com/adevinta/vulcan-local/pkg/config"
	report "github.com/adevinta/vulcan-report"
	"github.com/google/go-cmp/cmp"
	"github.com/google/go-cmp/cmp/cmpopts"
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

func TestIsExcluded(t *testing.T) {

	tests := []struct {
		name                  string
		extendedVulnerability *ExtendedVulnerability
		exlusions             []config.Exclusion
		want                  bool
		wantErr               error
	}{
		{
			name: "ExcludedByTarget",
			extendedVulnerability: &ExtendedVulnerability{
				CheckData: &report.CheckData{
					ChecktypeName:    "vulcan-trivy",
					ChecktypeVersion: "latest",
					Status:           "FINISHED",
					Target:           "appsecco/dsvw:latest",
				},
				Vulnerability: &report.Vulnerability{
					ID: "",
				},
				Severity: &config.SeverityData{
					Severity:  config.SeverityInfo,
					Name:      "INFO",
					Threshold: 0,
					Exit:      config.SuccessExitCode,
					Color:     36, // Light blue
				},
				Excluded: false,
			},
			exlusions: []config.Exclusion{
				{
					Target: "appsecco/dsvw:latest",
				},
			},

			want:    true,
			wantErr: nil,
		},
		{
			name: "NonExcluded",
			extendedVulnerability: &ExtendedVulnerability{
				CheckData: &report.CheckData{
					ChecktypeName:    "vulcan-trivy",
					ChecktypeVersion: "latest",
					Status:           "FINISHED",
					Target:           "appsecco/dsvw:latest",
				},
				Vulnerability: &report.Vulnerability{
					ID: "",
				},
				Severity: &config.SeverityData{
					Severity:  config.SeverityInfo,
					Name:      "INFO",
					Threshold: 0,
					Exit:      config.SuccessExitCode,
					Color:     36, // Light blue
				},
				Excluded: false,
			},
			exlusions: []config.Exclusion{
				{
					Target: "abc/dsvw:latest",
				},
			},

			want:    false,
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			got := isExcluded(tt.extendedVulnerability, &tt.exlusions)

			diff := cmp.Diff(got, tt.want)
			if diff != "" {
				t.Errorf("%v\n", diff)
			}
		})
	}
}

func TestParseReports(t *testing.T) {
	tests := []struct {
		name    string
		reports map[string]*report.Report
		cfg     *config.Config
		want    []ExtendedVulnerability
	}{
		{
			name: "HappyPath",
			cfg: &config.Config{
				Checks: []config.Check{
					{
						Id:        "FINISHED",
						Type:      "vulcan-trivy",
						Target:    "appsecco/dsvw:latest",
						AssetType: "DockerImage",
						NewTarget: "",
						Checktype: &checktypes.Checktype{
							RequiredVars: []string{"OPTVAR"},
						},
					},
				},
			},
			reports: map[string]*report.Report{
				"FINISHED": {
					CheckData: report.CheckData{
						ChecktypeName:    "vulcan-trivy",
						ChecktypeVersion: "latest",
						Status:           "FINISHED",
						Target:           "appsecco/dsvw:latest",
					},
					ResultData: report.ResultData{
						Vulnerabilities: []report.Vulnerability{{ID: "foo"}},
					},
				},
			},
			want: []ExtendedVulnerability{
				{
					CheckData: &report.CheckData{
						ChecktypeName:    "vulcan-trivy",
						ChecktypeVersion: "latest",
						Status:           "FINISHED",
						Target:           "appsecco/dsvw:latest",
					},
					Vulnerability: &report.Vulnerability{ID: "foo"},
					Severity:      config.SeverityInfo.Data(),
					Excluded:      false,
				},
			},
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			got := parseReports(tt.reports, tt.cfg, loggerUser)
			diff := cmp.Diff(got, tt.want)
			if diff != "" {
				t.Errorf("%v\n", diff)
			}
		})
	}
}

func TestCheckRequiredVars(t *testing.T) {
	buf := bytes.Buffer{}
	loggerUser.SetOutput(&buf)
	tests := []struct {
		name        string
		reports     map[string]*report.Report
		cfg         *config.Config
		want        []ExtendedVulnerability
		wantLog     string
		dontWantLog string
	}{
		{
			name: "HappyPath",
			cfg: &config.Config{
				Conf: config.Conf{
					Vars: map[string]string{},
				},
				Checks: []config.Check{
					{
						Id:        "FINISHED",
						Type:      "vulcan-trivy",
						Target:    "appsecco/dsvw:latest",
						AssetType: "DockerImage",
						NewTarget: "",
						Checktype: &checktypes.Checktype{
							RequiredVars: []string{"OPTVAR"},
						},
					},
				},
			},
			reports: map[string]*report.Report{
				"FINISHED": {
					CheckData: report.CheckData{
						ChecktypeName:    "vulcan-trivy",
						ChecktypeVersion: "latest",
						Status:           "FINISHED",
						Target:           "appsecco/dsvw:latest",
					},
				},
			},
			wantLog:     "",       // If the check fails and the variable was set a log is expected.
			dontWantLog: "OPTVAR", // If the check finishes we don't expect a log.
		},
		{
			name: "FailedWithInformedVars",
			cfg: &config.Config{
				Conf: config.Conf{
					Vars: map[string]string{
						"VAR": "VALUE",
					},
				},
				Checks: []config.Check{
					{
						Id:        "XX",
						Type:      "vulcan-trivy",
						Target:    "appsecco/dsvw:latest",
						AssetType: "DockerImage",
						NewTarget: "",
						Checktype: &checktypes.Checktype{
							RequiredVars: []string{"VAR"},
						},
					},
				},
			},
			reports: map[string]*report.Report{
				"XX": {
					CheckData: report.CheckData{
						ChecktypeName:    "vulcan-trivy",
						ChecktypeVersion: "latest",
						Status:           "FAILED",
						Target:           "appsecco/dsvw:latest",
					},
				},
			},
			wantLog:     "",    // If the check fails and the variable was set a log is expected.
			dontWantLog: "VAR", // If the check finishes we don't expect a log.
		},
		{
			name: "FailedWithUnInformedVars",
			cfg: &config.Config{
				Conf: config.Conf{
					Vars: map[string]string{},
				},
				Checks: []config.Check{
					{
						Id:        "XX",
						Type:      "vulcan-trivy",
						Target:    "appsecco/dsvw:latest",
						AssetType: "DockerImage",
						NewTarget: "",
						Checktype: &checktypes.Checktype{
							RequiredVars: []string{"VAR"},
						},
					},
				},
			},
			reports: map[string]*report.Report{
				"XX": {
					CheckData: report.CheckData{
						ChecktypeName:    "vulcan-trivy",
						ChecktypeVersion: "latest",
						Status:           "FAILED",
						Target:           "appsecco/dsvw:latest",
					},
				},
			},
			wantLog:     "VAR", // If the check fails and the variable was set a log is expected.
			dontWantLog: "",    // If the check finishes we don't expect a log.
		},
		{
			name: "CrashedWithUnInformedVars",
			cfg: &config.Config{
				Conf: config.Conf{
					Vars: map[string]string{},
				},
				Checks: []config.Check{
					{
						Id:        "XX",
						Type:      "vulcan-trivy",
						Target:    "appsecco/dsvw:latest",
						AssetType: "DockerImage",
						NewTarget: "",
						Checktype: &checktypes.Checktype{
							RequiredVars: []string{"VAR"},
						},
					},
				},
			},
			reports:     map[string]*report.Report{},
			wantLog:     "VAR", // If the check fails and the variable was set a log is expected.
			dontWantLog: "",    // If the check finishes we don't expect a log.
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			loggerUser.SetLevel(agentlog.ParseLogLevel("INFO"))
			checkRequiredVariables(tt.cfg, tt.reports, loggerUser)
			if tt.wantLog != "" && !strings.Contains(buf.String(), tt.wantLog) {
				t.Errorf("Missing log %s", tt.wantLog)
			}
			if tt.dontWantLog != "" && strings.Contains(buf.String(), tt.dontWantLog) {
				t.Errorf("Unexpected log %s", tt.wantLog)
			}
			buf.Reset()
		})
	}
}

func TestUpdateReport(t *testing.T) {
	tests := []struct {
		name                  string
		extendedVulnerability *ExtendedVulnerability
		check                 *config.Check
		want                  ExtendedVulnerability
		wantErr               error
	}{
		{
			name: "HappyPath",
			extendedVulnerability: &ExtendedVulnerability{
				CheckData: &report.CheckData{
					ChecktypeName:    "vulcan-trivy",
					ChecktypeVersion: "latest",
					Status:           "FINISHED",
					Target:           "appsecco/dsvw:latest",
				},
				Vulnerability: &report.Vulnerability{
					ID: "",
				},
				Severity: &config.SeverityData{},
				Excluded: false,
			},
			check: &config.Check{
				Type:      "vulcan-trivy",
				Target:    "appsecco/dsvw:latest",
				AssetType: "DockerImage",
				NewTarget: "",
			},
			want: ExtendedVulnerability{
				CheckData: &report.CheckData{
					ChecktypeName:    "vulcan-trivy",
					ChecktypeVersion: "latest",
					Status:           "FINISHED",
					Target:           "appsecco/dsvw:latest",
				},
				Vulnerability: &report.Vulnerability{
					ID: "",
				},
				Severity: &config.SeverityData{},
				Excluded: false,
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			updateReport(tt.extendedVulnerability, tt.check)

			diff := cmp.Diff(tt.extendedVulnerability, &tt.want,
				cmpopts.IgnoreFields(report.CheckData{}, "CheckID", "StartTime", "EndTime"),
				cmpopts.IgnoreFields(report.Vulnerability{}, "Fingerprint"),
				cmpopts.IgnoreFields(config.Check{}, "Id"),
			)
			if diff != "" {
				t.Errorf("%v\n", diff)
			}
		})
	}
}
