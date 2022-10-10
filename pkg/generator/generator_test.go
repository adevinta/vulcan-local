/*
Copyright 2022 Adevinta
*/

package generator

import (
	"errors"
	"os"
	"regexp"
	"testing"
	"time"

	"github.com/adevinta/vulcan-agent/jobrunner"
	"github.com/adevinta/vulcan-local/pkg/checktypes"
	"github.com/adevinta/vulcan-local/pkg/config"
	"github.com/adevinta/vulcan-local/pkg/gitservice"
	"github.com/adevinta/vulcan-local/pkg/testutil"
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

func errToStr(err error) string {
	return testutil.ErrToStr(err)
}

func TestGetCheckType(t *testing.T) {

	tests := []struct {
		name         string
		ct           checktypes.Checktypes
		checkTypeRef checktypes.ChecktypeRef
		want         *checktypes.Checktype
		wantErr      error
	}{
		{
			name: "HappyPath",
			ct: checktypes.Checktypes{
				"vulcan-zap": {
					Name: "vulcan-zap",
				},
			},
			checkTypeRef: "vulcan-zap",
			want: &checktypes.Checktype{
				Name: "vulcan-zap",
			},
			wantErr: nil,
		},
		{
			name: "CheckNotFound",
			ct: checktypes.Checktypes{
				"vulcan-zap": {
					Name: "vulcan-zap",
				},
			},
			checkTypeRef: "vulcan-trivy",
			want:         nil,
			wantErr:      errors.New("unable to find checktype ref vulcan-trivy"),
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			got, err := tt.ct.Checktype(tt.checkTypeRef)
			if errToStr(err) != errToStr(tt.wantErr) {
				t.Fatal(err)
			}
			diff := cmp.Diff(got, tt.want)
			if diff != "" {
				t.Errorf("%v\n", diff)
			}
		})
	}

}

func TestMergeOptions(t *testing.T) {
	tests := []struct {
		name    string
		optsA   map[string]interface{}
		optsB   map[string]interface{}
		want    map[string]interface{}
		wantErr error
	}{
		{
			name: "Disjoint",
			optsA: map[string]interface{}{
				"A": "A",
				"B": "B",
			},
			optsB: map[string]interface{}{
				"C": "C",
				"D": "D",
			},
			want: map[string]interface{}{
				"A": "A",
				"B": "B",
				"C": "C",
				"D": "D",
			},
			wantErr: nil,
		},
		{
			name: "Two maps with a common element with different value",
			optsA: map[string]interface{}{
				"A": "A",
				"B": "B",
			},
			optsB: map[string]interface{}{
				"B": "C",
				"D": "D",
			},
			want: map[string]interface{}{
				"A": "A",
				"B": "C",
				"D": "D",
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			got := mergeOptions(tt.optsA, tt.optsB)

			diff := cmp.Diff(got, tt.want)
			if diff != "" {
				t.Errorf("%v\n", diff)
			}
		})
	}
}

func TestGenerateJobs(t *testing.T) {

	gs := gitservice.New(loggerUser)
	defer gs.Shutdown()

	tests := []struct {
		name    string
		cfg     *config.Config
		want    []jobrunner.Job
		wantErr error
	}{
		{
			name: "HappyPath",
			cfg: &config.Config{
				CheckTypes: map[checktypes.ChecktypeRef]checktypes.Checktype{
					"vulcan-trivy": {
						Name: "vulcan-trivy",
					},
				},
				Checks: []config.Check{
					{
						Type:      "vulcan-trivy",
						Target:    "git@github.com:adevinta/vulcan-local.git",
						AssetType: "GitRepository",
					},
				},
			},
			want: []jobrunner.Job{
				{
					Target:    "git@github.com:adevinta/vulcan-local.git",
					AssetType: "GitRepository",
					Options:   "{}",
				},
			},
			wantErr: nil,
		},
		{
			name: "Exclude Trivy",
			cfg: &config.Config{
				CheckTypes: map[checktypes.ChecktypeRef]checktypes.Checktype{
					"vulcan-trivy": {
						Name: "vulcan-trivy",
					},
				},
				Checks: []config.Check{
					{
						Type:      "vulcan-trivy",
						Target:    "git@github.com:adevinta/vulcan-local.git",
						AssetType: "GitRepository",
					},
				},
				Conf: config.Conf{
					ExcludeR: func() *regexp.Regexp { regex, _ := regexp.Compile("trivy"); return regex }(),
				},
			},
			want:    []jobrunner.Job{},
			wantErr: nil,
		},
		{
			name: "Duplicated check",
			cfg: &config.Config{
				CheckTypes: map[checktypes.ChecktypeRef]checktypes.Checktype{
					"vulcan-trivy": {
						Name: "vulcan-trivy",
					},
				},
				Checks: []config.Check{
					{
						Type:      "vulcan-trivy",
						Target:    "git@github.com:adevinta/vulcan-local.git",
						AssetType: "GitRepository",
					},
					{
						Type:      "vulcan-trivy",
						Target:    "git@github.com:adevinta/vulcan-local.git",
						AssetType: "GitRepository",
					},
				},
			},
			want: []jobrunner.Job{
				{
					Target:    "git@github.com:adevinta/vulcan-local.git",
					AssetType: "GitRepository",
					Options:   "{}",
				},
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			got, err := GenerateJobs(tt.cfg, "", "", gs, loggerUser)
			if errToStr(err) != errToStr(tt.wantErr) {
				t.Fatal(err)
			}
			diff := cmp.Diff(got, tt.want, cmpopts.IgnoreFields(jobrunner.Job{}, "CheckID", "StartTime"))
			if diff != "" {
				t.Errorf("%v\n", diff)
			}
		})
	}
}

func TestBuildOptions(t *testing.T) {
	tests := []struct {
		name    string
		options map[string]interface{}
		want    string
		wantErr error
	}{
		{
			name: "Single Option",
			options: map[string]interface{}{
				"A": "A",
			},
			want:    "{\"A\":\"A\"}",
			wantErr: nil,
		},
		{
			name: "Mixed types options",
			options: map[string]interface{}{
				"A": "A",
				"B": 3,
			},
			want:    "{\"A\":\"A\",\"B\":3}",
			wantErr: nil,
		},
		{
			name:    "Missing options",
			want:    "{}",
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			got, err := buildOptions(tt.options)
			if errToStr(err) != errToStr(tt.wantErr) {
				t.Fatal(err)
			}
			diff := cmp.Diff(got, tt.want)
			if diff != "" {
				t.Errorf("%v\n", diff)
			}
		})
	}
}

func TestFilterCheckType(t *testing.T) {
	tests := []struct {
		name          string
		nameCheckType string
		include       string
		exclude       string
		want          bool
	}{
		{
			name:          "Is included",
			nameCheckType: "vulcan-trivy",
			include:       "trivy",
			exclude:       "",
			want:          true,
		},
		{
			name:          "Is excluded",
			nameCheckType: "vulcan-trivy",
			include:       "",
			exclude:       "trivy",
			want:          false,
		},
		{
			name:          "If included and excluded then it's excluded",
			nameCheckType: "vulcan-trivy",
			include:       "trivy",
			exclude:       "trivy",
			want:          false,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			var includeR *regexp.Regexp = nil
			var excludeR *regexp.Regexp = nil

			if tt.include != "" {
				includeR, _ = regexp.Compile(tt.include)
			}

			if tt.exclude != "" {
				excludeR, _ = regexp.Compile(tt.exclude)
			}

			got := filterChecktype(tt.nameCheckType, includeR, excludeR)
			diff := cmp.Diff(got, tt.want)
			if diff != "" {
				t.Errorf("%v\n", diff)
			}
		})
	}
}

func TestGetTypesFromIdentifier(t *testing.T) {

	tests := []struct {
		name    string
		target  config.Target
		want    []config.Target
		wantErr error
	}{
		{
			name: "Resolve to WebAddress",
			target: config.Target{
				Target:  "http://localhost:1234/",
				Options: map[string]interface{}{"max_scan_duration": 1},
			},
			want: []config.Target{
				{
					Target:    "http://localhost:1234/",
					Options:   map[string]interface{}{"max_scan_duration": 1},
					AssetType: "WebAddress",
				},
			},
			wantErr: nil,
		},
		{
			name: "Resolve to Hostname and DomainName",
			target: config.Target{
				Target: "example.com",
			},
			want: []config.Target{
				{
					Target:    "example.com",
					AssetType: "Hostname",
				},
				{
					Target:    "example.com",
					AssetType: "DomainName",
				},
			},
			wantErr: nil,
		},
		{
			name: "Resolve to IP",
			target: config.Target{
				Target: "127.0.0.1",
			},
			want: []config.Target{
				{
					Target:    "127.0.0.1",
					AssetType: "IP",
				},
			},
			wantErr: nil,
		},
		{
			name: "Resolve to IPRange",
			target: config.Target{
				Target: "192.0.2.1/24",
			},
			want: []config.Target{
				{
					Target:    "192.0.2.1/24",
					AssetType: "IPRange",
				},
			},
			wantErr: nil,
		},
		{
			name: "Resolve range to IP",
			target: config.Target{
				Target: "192.0.2.1/32",
			},
			want: []config.Target{
				{
					Target:    "192.0.2.1",
					AssetType: "IP",
				},
			},
			wantErr: nil,
		},
		{
			name: "Resolve to AWSAccount",
			target: config.Target{
				Target: "arn:aws:s3:::my_corporate_bucket/exampleobject.png",
			},
			want: []config.Target{
				{
					Target:    "arn:aws:s3:::my_corporate_bucket/exampleobject.png",
					AssetType: "AWSAccount",
				},
			},
			wantErr: nil,
		},
		{
			name: "Resolve to DockerImage",
			target: config.Target{
				Target: "registry.hub.docker.com/artifact",
			},
			want: []config.Target{
				{
					Target:    "registry.hub.docker.com/artifact",
					AssetType: "DockerImage",
				},
			},
			wantErr: nil,
		},
		{
			name: "Resolve to GitRepository",
			target: config.Target{
				Target: "git@github.com:adevinta/vulcan-local.git",
			},
			want: []config.Target{
				{
					Target:    "git@github.com:adevinta/vulcan-local.git",
					AssetType: "GitRepository",
				},
			},
			wantErr: nil,
		},
		{
			name: "Resolve to local GitRepository",
			target: config.Target{
				Target: ".",
			},
			want: []config.Target{
				{
					Target:    ".",
					AssetType: "GitRepository",
				},
			},
			wantErr: nil,
		},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			got, err := getTypesFromIdentifier(tt.target)
			if errToStr(err) != errToStr(tt.wantErr) {
				t.Fatal(err)
			}
			diff := cmp.Diff(got, tt.want)
			if diff != "" {
				t.Errorf("%v\n", diff)
			}
		})
	}
}

func TestComputeTargets(t *testing.T) {

	tests := []struct {
		name    string
		cfg     *config.Config
		want    []config.Target
		wantErr error
	}{
		{
			name: "HappyPath",
			cfg: &config.Config{
				CheckTypes: map[checktypes.ChecktypeRef]checktypes.Checktype{
					"vulcan-zap": {
						Name: "vulcan-zap",
					},
				},
				Targets: []config.Target{
					{
						Target: "registry.hub.docker.com/artifact",
					},
				},
			},
			want: []config.Target{
				{
					Target:    "registry.hub.docker.com/artifact",
					AssetType: "DockerImage",
				},
			},
			wantErr: nil,
		},
		{
			name: "DuplicatedTargets",
			cfg: &config.Config{
				CheckTypes: map[checktypes.ChecktypeRef]checktypes.Checktype{
					"vulcan-zap": {
						Name: "vulcan-zap",
					},
				},
				Targets: []config.Target{
					{
						Target: "registry.hub.docker.com/artifact",
					},
					{
						Target: "registry.hub.docker.com/artifact",
					},
				},
			},
			want: []config.Target{
				{
					Target:    "registry.hub.docker.com/artifact",
					AssetType: "DockerImage",
				},
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			err := ComputeTargets(tt.cfg, loggerUser)
			if errToStr(err) != errToStr(tt.wantErr) {
				t.Fatal(err)
			}
			diff := cmp.Diff(tt.cfg.Targets, tt.want)
			if diff != "" {
				t.Errorf("%v\n", diff)
			}
		})
	}
}

func TestAddPolicyChecks(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.Config
		want    []config.Check
		wantErr error
	}{
		{
			name: "HappyPath",
			cfg: &config.Config{
				Conf: config.Conf{
					Policy: "lightweight",
				},
				CheckTypes: map[checktypes.ChecktypeRef]checktypes.Checktype{
					"vulcan-zap": {
						Name:   "vulcan-zap",
						Assets: []string{"GitRepository"},
					},
					"vulcan-trivy": {
						Name:   "vulcan-trivy",
						Assets: []string{"GitRepository"},
					},
				},
				Policies: []config.Policy{
					{
						Name: "lightweight",
						CheckTypes: []config.PolicyCheck{
							{
								CheckType: "vulcan-trivy",
							},
						},
					},
				},
				Targets: []config.Target{
					{
						Target:    "git@github.com:adevinta/vulcan-local.git",
						AssetType: "GitRepository",
					},
				},
			},
			want: []config.Check{
				{
					Type:      "vulcan-trivy",
					Target:    "git@github.com:adevinta/vulcan-local.git",
					Options:   map[string]interface{}{},
					AssetType: "GitRepository",
				},
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			err := AddPolicyChecks(tt.cfg, loggerUser)
			if errToStr(err) != errToStr(tt.wantErr) {
				t.Fatal(err)
			}
			diff := cmp.Diff(tt.cfg.Checks, tt.want)
			if diff != "" {
				t.Errorf("%v\n", diff)
			}
		})
	}
}

func TestAddAllChecks(t *testing.T) {
	tests := []struct {
		name    string
		cfg     *config.Config
		want    []config.Check
		wantErr error
	}{
		{
			name: "HappyPath",
			cfg: &config.Config{
				CheckTypes: map[checktypes.ChecktypeRef]checktypes.Checktype{
					"vulcan-zap": {
						Name:   "vulcan-zap",
						Assets: []string{"GitRepository"},
					},
					"vulcan-trivy": {
						Name:   "vulcan-trivy",
						Assets: []string{"GitRepository"},
					},
				},
				Targets: []config.Target{
					{
						Target:    "git@github.com:adevinta/vulcan-local.git",
						AssetType: "GitRepository",
					},
				},
			},
			want: []config.Check{
				{
					Type:      "vulcan-zap",
					Target:    "git@github.com:adevinta/vulcan-local.git",
					Options:   map[string]interface{}{},
					AssetType: "GitRepository",
				},
				{
					Type:      "vulcan-trivy",
					Target:    "git@github.com:adevinta/vulcan-local.git",
					Options:   map[string]interface{}{},
					AssetType: "GitRepository",
				},
			},
			wantErr: nil,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {

			err := AddAllChecks(tt.cfg, loggerUser)
			if errToStr(err) != errToStr(tt.wantErr) {
				t.Fatal(err)
			}

			sortCfgChecks := cmpopts.SortSlices(func(a config.Check, b config.Check) bool {
				return a.Type < b.Type
			})

			diff := cmp.Diff(tt.cfg.Checks, tt.want, sortCfgChecks)

			if diff != "" {
				t.Errorf("%v\n", diff)
			}
		})
	}
}
