/*
Copyright 2021 Adevinta
*/

package config

import (
	"fmt"
	neturl "net/url"
	"reflect"
	"regexp"
	"strings"

	agentconfig "github.com/adevinta/vulcan-agent/config"
	"github.com/adevinta/vulcan-agent/log"
	"github.com/drone/envsubst"
	"github.com/imdario/mergo"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"

	"github.com/adevinta/vulcan-local/pkg/checktypes"
	"github.com/adevinta/vulcan-local/pkg/content"
)

type Check struct {
	Type      checktypes.ChecktypeRef `yaml:"type"`
	Target    string                  `yaml:"target"`
	Options   map[string]interface{}  `yaml:"options,omitempty"`
	Timeout   *int                    `yaml:"timeout,omitempty"`
	AssetType string                  `yaml:"assetType,omitempty"`
	NewTarget string
	Id        string
	Checktype *checktypes.Checktype
}

type Target struct {
	Target    string                 `yaml:"target"`
	AssetType string                 `yaml:"assetType"`
	Options   map[string]interface{} `yaml:"options,omitempty"`
}

type Config struct {
	Conf       Conf                  `yaml:"conf"`
	Reporting  Reporting             `yaml:"reporting,omitempty"`
	Checks     []Check               `yaml:"checks"`
	Targets    []Target              `yaml:"targets"`
	CheckTypes checktypes.Checktypes `yaml:"checkTypes"`
	Policies   []Policy              `yaml:"policies"`
}

type Policy struct {
	Name       string        `yaml:"name"`
	CheckTypes []PolicyCheck `yaml:"checks"`
}

type PolicyCheck struct {
	CheckType checktypes.ChecktypeRef `yaml:"type"`
	Options   map[string]interface{}  `yaml:"options,omitempty"`
}

type Registry struct {
	Server   string `yaml:"server"`
	Username string `yaml:"username"`
	Password string `yaml:"password"`
}

type Conf struct {
	DockerBin    string                 `yaml:"dockerBin"`
	GitBin       string                 `yaml:"gitBin"`
	PullPolicy   agentconfig.PullPolicy `yaml:"pullPolicy"`
	Vars         map[string]string      `yaml:"vars"`
	Repositories []string               `yaml:"repositories"`
	Registries   []Registry             `yaml:"registries"`
	LogLevel     logrus.Level           `yaml:"logLevel"`
	Concurrency  int                    `yaml:"concurrency"`
	IfName       string                 `yaml:"ifName"`
	Exclude      string                 `yaml:"exclude"`
	Include      string                 `yaml:"include"`
	IncludeR     *regexp.Regexp
	ExcludeR     *regexp.Regexp
	Policy       string
}

type Exclusion struct {
	Target           string `yaml:"target"`
	Summary          string `yaml:"summary"`
	AffectedResource string `yaml:"affectedResource"`
	Fingerprint      string `yaml:"fingerprint"`
	Description      string `yaml:"description"`
}

type Reporting struct {
	Severity   Severity     `yaml:"severity"`
	Format     ReportFormat `yaml:"format"`
	OutputFile string       `yaml:"outputFile"`
	Exclusions []Exclusion  `yaml:"exclusions"`
}

type Severity int

const (
	SeverityCritical Severity = iota
	SeverityHigh
	SeverityMedium
	SeverityLow
	SeverityInfo
)

type ReportFormat int

const (
	FormatJSON ReportFormat = iota
	FormatReport
)

const (
	ErrorExitCode   = 1
	SuccessExitCode = 0
)

type SeverityData struct {
	Severity  Severity
	Name      string
	Threshold float32
	Exit      int
	Color     int
}

var severities = []SeverityData{
	{
		Severity:  SeverityCritical,
		Name:      "CRITICAL",
		Threshold: 9.0,
		Exit:      104,
		Color:     35, // Purple
	},
	{
		Severity:  SeverityHigh,
		Name:      "HIGH",
		Threshold: 7.0,
		Exit:      103,
		Color:     31, // Red
	},
	{
		Severity:  SeverityMedium,
		Name:      "MEDIUM",
		Threshold: 4.0,
		Exit:      102,
		Color:     33, // Yellow
	},
	{
		Severity:  SeverityLow,
		Name:      "LOW",
		Threshold: 0.1,
		Exit:      101,
		Color:     36, // Light blue
	},
	{
		Severity:  SeverityInfo,
		Name:      "INFO",
		Threshold: 0,
		Exit:      SuccessExitCode,
		Color:     36, // Light blue
	},
}

// MarshalText returns string representation of a Severity instance.
func (a *Severity) MarshalText() (text []byte, err error) {
	s, err := a.String()
	if err != nil {
		return nil, err
	}
	return []byte(s), nil
}

// UnmarshalText creates a Severity from its string representation.
func (a *Severity) UnmarshalText(text []byte) error {
	val := string(text)
	for _, v := range severities {
		if v.Name == val {
			*a = v.Severity
			return nil
		}
	}
	return fmt.Errorf("error value %s is not a valid Severity value", val)
}

func SeverityNames() []string {
	s := []string{}
	for _, v := range severities {
		s = append(s, v.Name)
	}
	return s
}

func Severities() []Severity {
	s := []Severity{}
	for _, v := range severities {
		s = append(s, v.Severity)
	}
	return s
}

func (a Severity) String() (string, error) {
	return a.Data().Name, nil
}

func (a Severity) Data() *SeverityData {
	for _, v := range severities {
		if v.Severity == a {
			return &v
		}
	}
	return &SeverityData{}
}

func FindSeverityByScore(score float32) Severity {
	for _, s := range severities {
		if score >= s.Threshold {
			return s.Severity
		}
	}
	return severities[len(severities)-1].Severity
}

var reportFormatString = map[ReportFormat]string{
	FormatJSON:   "json",
	FormatReport: "report",
}

func (f *ReportFormat) String() string {
	if a, ok := reportFormatString[*f]; ok {
		return a
	}
	return "unknown"
}

func (a *ReportFormat) MarshalText() (text []byte, err error) {
	return []byte(a.String()), nil
}

// UnmarshalText creates a Severity from its string representation.
func (a *ReportFormat) UnmarshalText(text []byte) error {
	val := string(text)
	for k, v := range reportFormatString {
		if v == val {
			*a = k
			return nil
		}
	}
	return fmt.Errorf("error value %s is not a valid ReportFormat value", val)
}

func ReportFormatNames() []string {
	s := []string{}
	for _, v := range reportFormatString {
		s = append(s, v)
	}
	return s
}

func ReadConfig(url string, cfg *Config, l log.Logger) error {
	if strings.HasPrefix(url, "file://") {
		l.Infof("Removing 'file://' from %s. This support will be deprecated in future versions", url)
		url = strings.TrimPrefix(url, "file://")
	}

	u, err := neturl.Parse(url)
	if err != nil {
		return err
	}
	bytes, err := content.Download(u)
	if err != nil {
		return err
	}

	c, err := envsubst.EvalEnv(string(bytes))
	if err != nil {
		return fmt.Errorf("unable to eval envs in %s: %w", url, err)
	}
	bytes = []byte(c)
	newConfig := Config{}
	err = yaml.Unmarshal(bytes, &newConfig)
	if err != nil {
		return fmt.Errorf("unable to decode yaml %s: %w", url, err)
	}
	if err = mergo.Merge(cfg, newConfig, mergo.WithTransformers(sliceAppenderTransformer{})); err != nil {
		return fmt.Errorf("unable to merge config %s: %w", url, err)
	}
	l.Infof("Loaded config from url=%s", url)
	return nil
}

type sliceAppenderTransformer struct {
}

func (t sliceAppenderTransformer) Transformer(typ reflect.Type) func(dst, src reflect.Value) error {
	if typ.Kind() == reflect.Slice {
		return func(dst, src reflect.Value) error {
			if dst.CanSet() {
				dst.Set(reflect.AppendSlice(dst, src))
			}
			return nil
		}
	}
	return nil
}
