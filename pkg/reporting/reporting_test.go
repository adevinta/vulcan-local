/*
Copyright 2022 Adevinta
*/
package reporting

import (
	"os"
	"testing"
	"time"

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
		wantErr error
	}{
		{
			name: "HappyPath",
			reports: map[string]*report.Report{
				"12345": {
					CheckData: report.CheckData{
						ChecktypeName:    "vulcan-trivy",
						ChecktypeVersion: "latest",
						Status:           "FINISHED",
						Target:           "appsecco/dsvw:latest",
					},
					ResultData: report.ResultData{
						Vulnerabilities: []report.Vulnerability{
							{ID: ""},
						},
					},
				},
			},
			cfg: &config.Config{
				Checks: []config.Check{
					{
						Type:      "vulcan-trivy",
						Target:    "appsecco/dsvw:latest",
						AssetType: "DockerImage",
						NewTarget: "",
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
			},
			wantErr: nil,
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
