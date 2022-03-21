/*
Copyright 2021 Adevinta
*/

package config

import (
	"encoding/json"
	"fmt"
	"io/ioutil"
	"net/http"
	"os"
	"regexp"
	"strings"
	"time"

	agentconfig "github.com/adevinta/vulcan-agent/config"
	"github.com/adevinta/vulcan-agent/log"
	"github.com/drone/envsubst"
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
	LogLevel     string                 `yaml:"logLevel"`
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

func GetManifestFromUrl(url string) ([]Checktype, error) {
	client := http.Client{
		Timeout: time.Second * 10,
	}
	req, err := http.NewRequest(http.MethodGet, url, nil)
	if err != nil {
		return nil, err
	}
	res, err := client.Do(req)
	if err != nil {
		return nil, err
	}
	if res.Body != nil {
		defer res.Body.Close()
	}
	body, err := ioutil.ReadAll(res.Body)
	if err != nil {
		return nil, err
	}
	ct := Manifest{}
	err = json.Unmarshal(body, &ct)
	if err != nil {
		return nil, err
	}

	return ct.CheckTypes, nil
}

func GetManifestFromFile(path string) ([]Checktype, error) {
	body, err := ioutil.ReadFile(path)
	if err != nil {
		return nil, err
	}
	ct := Manifest{}
	err = json.Unmarshal(body, &ct)
	if err != nil {
		return nil, err
	}
	return ct.CheckTypes, nil
}

func ReadConfig(path string, cfg *Config, l log.Logger) error {
	var bytes []byte
	var err error
	if path == "-" {
		bytes, err = ioutil.ReadAll(os.Stdin)
	} else {
		bytes, err = ioutil.ReadFile(path)
	}
	if err != nil {
		return err
	}

	c, err := envsubst.EvalEnv(string(bytes))
	if err != nil {
		return err
	}
	bytes = []byte(c)
	err = yaml.Unmarshal(bytes, cfg)
	if err != nil {
		return err
	}

	if (*cfg).CheckTypes == nil {
		(*cfg).CheckTypes = make(map[ChecktypeRef]Checktype)
	}
	return nil
}

func AddRepo(cfg *Config, uri string, l log.Logger) error {
	var ct []Checktype
	var err error
	switch {
	case strings.HasPrefix(uri, "http://") || strings.HasPrefix(uri, "https://"):
		ct, err = GetManifestFromUrl(uri)
	case strings.HasPrefix(uri, "file://"):
		ct, err = GetManifestFromFile(strings.TrimPrefix(uri, "file://"))
	default:
		err = fmt.Errorf("invalid repository uri")
	}
	if err != nil {
		return err
	}
	for _, c := range ct {
		cfg.CheckTypes[ChecktypeRef(c.Name)] = c
	}
	l.Infof("Loaded checktypes uri=%s checktypes=%d", uri, len(ct))
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
