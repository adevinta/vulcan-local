/*
Copyright 2021 Adevinta
*/

package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"reflect"
	"regexp"
	"strings"
	"time"

	agentconfig "github.com/adevinta/vulcan-agent/config"
	"github.com/adevinta/vulcan-agent/log"
	"github.com/drone/envsubst"
	"github.com/imdario/mergo"
	"github.com/sirupsen/logrus"
	"gopkg.in/yaml.v3"
)

// ChektypeRef represents a checktype with an optional prefix denoting the repository (i.e. default/vulcan-zap vulcan-zap ).
type ChecktypeRef string

type Check struct {
	Type      ChecktypeRef           `yaml:"type"`
	Target    string                 `yaml:"target"`
	Options   map[string]interface{} `yaml:"options,omitempty"`
	Timeout   *int                   `yaml:"timeout,omitempty"`
	AssetType string                 `yaml:"assetType,omitempty"`
	NewTarget string
	Id        string
	Checktype *Checktype
}

type Target struct {
	Target    string
	AssetType string
	Options   map[string]interface{}
}

type Config struct {
	Conf       Conf                       `yaml:"conf"`
	Reporting  Reporting                  `yaml:"reporting,omitempty"`
	Checks     []Check                    `yaml:"checks"`
	Targets    []Target                   `yaml:"targets"`
	CheckTypes map[ChecktypeRef]Checktype `yaml:"checkTypes"`
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
}

type Exclusion struct {
	Target           string `yaml:"target"`
	Summary          string `yaml:"summary"`
	AffectedResource string `yaml:"affectedResource"`
	Fingerprint      string `yaml:"fingerprint"`
}

type Reporting struct {
	Severity   Severity    `yaml:"severity"`
	Format     string      `yaml:"format"`
	OutputFile string      `yaml:"outputFile"`
	Exclusions []Exclusion `yaml:"exclusions"`
}

// Definition borrowed from vulcan-checks-bsys.
type Checktype struct {
	Name         string                 `json:"name"`
	Description  string                 `json:"description"`
	Timeout      int                    `json:"timeout,omitempty"`
	Image        string                 `json:"image"`
	Options      map[string]interface{} `json:"options,omitempty"`
	RequiredVars []string               `json:"required_vars"`
	QueueName    string                 `json:"queue_name,omitempty"`
	Assets       []string               `json:"assets"`
}

type Manifest struct {
	CheckTypes []Checktype
}

type Severity int

const (
	SeverityCritical Severity = iota
	SeverityHigh
	SeverityMedium
	SeverityLow
	SeverityInfo
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

func getUriContent(uri string) ([]byte, error) {
	if uri == "" {
		return nil, fmt.Errorf("empty uri")
	}
	if strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://") {
		client := http.Client{
			Timeout: time.Second * 10,
		}
		req, err := http.NewRequest(http.MethodGet, uri, nil)
		if err != nil {
			return nil, fmt.Errorf("unable to request uri %s: %w", uri, err)
		}
		res, err := client.Do(req)
		if err != nil {
			return nil, fmt.Errorf("unable to get uri %s: %w", uri, err)
		}
		if res.Body != nil {
			defer res.Body.Close()
		}
		body, err := ioutil.ReadAll(res.Body)
		if err != nil {
			return nil, fmt.Errorf("unable to read uri %s: %w", uri, err)
		}
		return body, nil
	}

	uri = strings.TrimPrefix(uri, "file://")
	body, err := ioutil.ReadFile(uri)
	if err != nil {
		return nil, fmt.Errorf("unable to read file %s: %w", uri, err)
	}
	return body, nil
}

func ReadConfig(uri string, cfg *Config, l log.Logger) error {
	bytes, err := getUriContent(uri)
	if err != nil {
		return err
	}

	c, err := envsubst.EvalEnv(string(bytes))
	if err != nil {
		return fmt.Errorf("unable to eval envs in %s: %w", uri, err)
	}
	bytes = []byte(c)
	newConfig := Config{}
	err = yaml.Unmarshal(bytes, &newConfig)
	if err != nil {
		return fmt.Errorf("unable to decode yaml %s: %w", uri, err)
	}

	if err = mergo.Merge(cfg, newConfig, mergo.WithTransformers(sliceAppenderTransformer{})); err != nil {
		return fmt.Errorf("unable to merge config %s: %w", uri, err)
	}
	l.Infof("Loaded config from uri=%s", uri)
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

func AddRepo(cfg *Config, uri string, l log.Logger) error {
	content, err := getUriContent(uri)
	if err != nil {
		return err
	}
	man := Manifest{}
	err = json.Unmarshal(content, &man)
	if err != nil {
		return err
	}

	for _, c := range man.CheckTypes {
		cfg.CheckTypes[ChecktypeRef(c.Name)] = c
	}
	l.Infof("Loaded checktypes uri=%s checktypes=%d", uri, len(man.CheckTypes))
	return nil
}

func GetCheckById(cfg *Config, id string) *Check {
	for i, c := range cfg.Checks {
		if c.Id == id {
			return &cfg.Checks[i]
		}
	}
	return nil
}
