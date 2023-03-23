/*
Copyright 2021 Adevinta
*/

package checktypes

import (
	"encoding/json"
	"errors"
	"fmt"
	neturl "net/url"
	"strings"

	"github.com/adevinta/vulcan-agent/log"

	"github.com/adevinta/vulcan-local/pkg/content"
)

var errNoExternalExclusionsDir = errors.New("the directory does not contian a checktype")

type Exclusion struct {
	Target           string `json:"target,omitempty" yaml:"target,omitempty"`
	Summary          string `json:"summary,omitempty" yaml:"summary,omitempty"`
	AffectedResource string `json:"affected_resource,omitempty" yaml:"affectedResource,omitempty"`
	Fingerprint      string `json:"fingerprint,omitempty" yaml:"fingerprint,omitempty"`
	Description      string `json:"description,omitempty" yaml:"description,omitempty"`
}

// JSONChecktypes defines the shape of a file containing the definition of a
// set of checkstypes.
type JSONExternalExcluions struct {
	Exclusions []Exclusion `json:"exclusions"`
}

// Import loads the information of the checktypes defined in the specified repos
// url's.
func ExclusionsImport(repos []string, l log.Logger) ([]Exclusion, error) {
	var exclusions = make([]Exclusion, 0)
	for _, repo := range repos {
		if strings.HasPrefix(repo, "file://") {
			l.Infof("Removing 'file://' from %s. This support will be deprecated in future versions", repo)
			repo = strings.TrimPrefix(repo, "file://")
		}

		l.Debugf("Importing exclusions from: %s", repo)
		repoURL, err := neturl.Parse(repo)
		if err != nil {
			return nil, err
		}
		rexclusions, err := exclusionsFromJSON(repoURL, l)
		if err != nil {
			return nil, err
		}
		exclusions = append(exclusions, rexclusions...)
		if err != nil {
			return nil, fmt.Errorf("unable to load repository %s: %w", repo, err)
		}
	}
	return exclusions, nil
}

func exclusionsFromJSON(u *neturl.URL, l log.Logger) ([]Exclusion, error) {
	content, err := content.Download(u)
	if err != nil {
		return nil, err
	}
	jexclusions := JSONExternalExcluions{}
	err = json.Unmarshal(content, &jexclusions)
	if err != nil {
		return nil, err
	}
	l.Debugf("Loaded exclusions from url=%s, number of exclusions loaded=%d", u.String(), len(jexclusions.Exclusions))
	return jexclusions.Exclusions, nil
}
