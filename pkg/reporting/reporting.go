/*
Copyright 2021 Adevinta
*/

package reporting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"time"

	"github.com/adevinta/vulcan-agent/log"
	"github.com/adevinta/vulcan-local/pkg/config"
	"github.com/adevinta/vulcan-local/pkg/results"
	report "github.com/adevinta/vulcan-report"
)

type Severity struct {
	Name      string
	Threshold float32
	Exit      int
	Color     int
}

const (
	ErrorExitCode   = 1
	SuccessExitCode = 0
)

var severities = []Severity{
	{
		Name:      "CRITICAL",
		Threshold: 9.0,
		Exit:      104,
		Color:     35, // Purple
	},
	{
		Name:      "HIGH",
		Threshold: 7.0,
		Exit:      103,
		Color:     31, // Red
	},
	{
		Name:      "MEDIUM",
		Threshold: 4.0,
		Exit:      102,
		Color:     33, // Yellow
	},
	{
		Name:      "LOW",
		Threshold: 0.1,
		Exit:      101,
		Color:     36, // Light blue
	},
	{
		Name:      "ALL",
		Threshold: 0,
		Exit:      SuccessExitCode,
		Color:     36, // Light blue
	},
}

func isExcluded(v *ExtendedVulnerability, ex *[]config.Exclusion) bool {
	for _, e := range *ex {
		if strings.Contains(v.Target, e.Target) &&
			strings.Contains(v.Summary, e.Summary) &&
			strings.Contains(v.Fingerprint, e.Fingerprint) &&
			(strings.Contains(v.AffectedResource, e.AffectedResource) || strings.Contains(v.AffectedResourceString, e.AffectedResource)) {
			return true
		}
	}
	return false
}

func updateReport(e *ExtendedVulnerability, c *config.Check) {
	e.Target = c.Target
	e.Details = strings.ReplaceAll(e.Details, c.NewTarget, c.Target)
	e.AffectedResource = strings.ReplaceAll(e.AffectedResource, c.NewTarget, c.Target)
	e.AffectedResourceString = strings.ReplaceAll(e.AffectedResourceString, c.NewTarget, c.Target)
	for i := range e.Recommendations {
		e.Recommendations[i] = strings.ReplaceAll(e.Recommendations[i], c.NewTarget, c.Target)
	}
	for re := range e.Resources {
		for r := range e.Resources[re].Rows {
			row := e.Resources[re].Rows[r]
			for k := range row {
				row[k] = strings.ReplaceAll(row[k], c.NewTarget, c.Target)
			}
		}
	}
}

func parseReports(reports map[string]*report.Report, cfg *config.Config, l log.Logger) []ExtendedVulnerability {
	vulns := []ExtendedVulnerability{}
	for _, r := range reports {
		for i := range r.Vulnerabilities {
			v := r.Vulnerabilities[i]
			extended := ExtendedVulnerability{
				CheckData:     &r.CheckData,
				Vulnerability: &v,
				Severity:      FindSeverityByScore(v.Score),
			}
			for _, s := range cfg.Checks {
				if s.Id == r.CheckID {
					updateReport(&extended, &s)
					break
				}
			}
			extended.Excluded = isExcluded(&extended, &cfg.Reporting.Exclusions)
			vulns = append(vulns, extended)
		}
	}
	return vulns
}

func FindSeverity(name string) (*Severity, error) {
	for i, t := range severities {
		if strings.EqualFold(name, t.Name) {
			return &severities[i], nil
		}
	}
	return nil, fmt.Errorf("invalid severity %s, allowed values %v", name, SeverityNames())
}

func SeverityNames() []string {
	names := []string{}
	for _, t := range severities {
		names = append(names, t.Name)
	}
	return names
}

func FindSeverityByScore(score float32) *Severity {
	for _, s := range severities {
		if score >= s.Threshold {
			return &s
		}
	}
	return &severities[len(severities)-1]
}

func ShowSummary(cfg *config.Config, results *results.ResultsServer, l log.Logger) {
	buf := new(bytes.Buffer)
	fmt.Fprint(buf, "\nCheck summary:\n\n")
	for _, c := range cfg.Checks {
		ct := c.Checktype
		if ct == nil {
			// The check was excluded by filters
			continue
		}
		status := "UNKNOWN"
		res, ok := results.Checks[c.Id]
		duration := 0.0
		if ok {
			status = res.Status

			// If not finished we use now as end time.
			if res.EndTime.IsZero() {
				duration = time.Since(res.StartTime).Seconds()
			} else {
				duration = res.EndTime.Sub(res.StartTime).Seconds()
			}
		}
		fmt.Fprintf(buf, " - image=%s target=%s assetType=%s status=%s duration=%f\n", ct.Image, c.Target, c.AssetType, status, duration)
	}
	fmt.Fprint(buf, "\n")
	l.Infof(buf.String())
}

func ShowProgress(cfg *config.Config, results *results.ResultsServer, l log.Logger) {
	statusMap := map[string]int{}
	for _, c := range cfg.Checks {
		ct := c.Checktype
		if ct == nil {
			// The check was excluded by filters
			continue
		}
		status := "UNKNOWN"
		res, ok := results.Checks[c.Id]
		if ok {
			status = res.Status
		}
		if n, ok := statusMap[status]; ok {
			statusMap[status] = n + 1
		} else {
			statusMap[status] = 1
		}
	}
	s := ""
	for k, v := range statusMap {
		s += fmt.Sprintf("%s:%d ", k, v)
	}
	l.Infof("Check progress [%s]", s)
}

func Generate(cfg *config.Config, results *results.ResultsServer, l log.Logger) (int, error) {
	if cfg.Reporting.Format != "json" {
		return 1, fmt.Errorf("report format unknown %s", cfg.Reporting.Format)
	}

	requested, err := FindSeverity(cfg.Reporting.Threshold)
	if err != nil {
		return ErrorExitCode, err
	}

	// Print results when no output file is set
	vs := parseReports(results.Checks, cfg, l)

	// Print summary table
	summaryTable(vs, l)

	outputFile := cfg.Reporting.OutputFile
	if outputFile != "" {
		// TODO: Decide if we want to keep filtering JSON output by threshold and exclusion
		// Recreates the original report map filtering the Excluded and Threshold
		// json: Just print the reports as an slice
		m := map[string]*report.Report{}
		slice := []*report.Report{}
		for _, e := range vs {
			r, ok := m[e.CheckID]
			if !ok {
				r = &report.Report{CheckData: *e.CheckData}
				m[e.CheckID] = r
				slice = append(slice, r)
			}
			if !e.Excluded && e.Severity.Threshold >= requested.Threshold {
				r.Vulnerabilities = append(r.Vulnerabilities, *(e.Vulnerability))
			}
		}
		str, _ := json.Marshal(slice)
		if outputFile == "-" {
			fmt.Fprint(os.Stderr, string(str))
		} else {
			f, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return 1, fmt.Errorf("unable to open report file %s %+v", outputFile, err)
			}
			defer f.Close()
			if _, err := f.Write(str); err != nil {
				return 1, fmt.Errorf("unable to write report file %s %+v", outputFile, err)
			}
		}
	}

	var rs string
	for _, s := range severities {
		for _, v := range vs {
			if v.Severity.Name == s.Name && !v.Excluded && v.Severity.Threshold >= requested.Threshold {
				rs = fmt.Sprintf("%s%s", rs, printVulnerability(&v, l))
			}
		}
	}
	if len(rs) > 0 {
		l.Infof("\nVulnerabilities details:\n%s", rs)
	}

	// Get max reported score in vulnerabilities
	var maxScore float32 = -1.0
	for _, v := range vs {
		if v.Score > float32(maxScore) {
			maxScore = v.Score
		}
	}

	if current := FindSeverityByScore(maxScore); current.Threshold >= requested.Threshold {
		return current.Exit, nil
	}

	return 0, nil
}
