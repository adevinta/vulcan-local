/*
Copyright 2021 Adevinta
*/

package reporting

import (
	"bytes"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/adevinta/vulcan-agent/log"
	"github.com/adevinta/vulcan-local/pkg/config"
	"github.com/adevinta/vulcan-local/pkg/results"
	report "github.com/adevinta/vulcan-report"
)

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
	if c.NewTarget == "" || c.NewTarget == c.Target {
		return
	}
	e.Target = c.Target
	e.Details = strings.ReplaceAll(e.Details, c.NewTarget, c.Target)
	e.AffectedResource = strings.ReplaceAll(e.AffectedResource, c.NewTarget, c.Target)
	e.AffectedResourceString = strings.ReplaceAll(e.AffectedResourceString, c.NewTarget, c.Target)
	e.ImpactDetails = strings.ReplaceAll(e.ImpactDetails, c.NewTarget, c.Target)
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

	for _, check := range cfg.Checks {
		// The check was filtered
		if check.Id == "" {
			continue
		}

		// See if the check received a report
		r, ok := reports[check.Id]
		if !ok {
			continue
		}

		for i := range r.Vulnerabilities {
			v := r.Vulnerabilities[i]
			extended := ExtendedVulnerability{
				CheckData:     &r.CheckData,
				Vulnerability: &v,
				Severity:      config.FindSeverityByScore(v.Score).Data(),
			}
			updateReport(&extended, &check)
			extended.Excluded = isExcluded(&extended, &cfg.Reporting.Exclusions)
			vulns = append(vulns, extended)
		}
	}
	return vulns
}

// checkExclusionDescriptions checks that the exlusions have the description
func checkExclusionDescriptions(cfg *config.Config, l log.Logger) {

	for _, e := range cfg.Reporting.Exclusions {
		if e.Description == "" {
			l.Infof("Missing description for the exclusion:\n"+
				" - Target: %s\n"+
				" - Summary: %s\n"+
				" - AffectedResource: %s\n"+
				" - Fingerprint:  %s\n",
				e.Target, e.Summary, e.AffectedResource, e.Fingerprint)

		}
	}
}

// checkRequiredVariables writes an error log for every scheduled check that failed with some reqvar empty.
func checkRequiredVariables(cfg *config.Config, reports map[string]*report.Report, l log.Logger) {
	for _, check := range cfg.Checks {
		// The check was filtered
		if check.Id == "" {
			continue
		}

		// See if the check received a report
		r, ok := reports[check.Id]

		// Write a log in case of failure and a missing req variable
		if !ok || r.Status != "FINISHED" {
			lv := []string{}
			for _, requiredVar := range check.Checktype.RequiredVars {
				if val, ok := cfg.Conf.Vars[requiredVar]; !ok || len(val) == 0 {
					lv = append(lv, requiredVar)
				}
			}
			if len(lv) > 0 {
				l.Errorf("Check %s on %s failed and %v variables where missing", check.Checktype.Name, check.Target, lv)
			}
		}
	}
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
	l.Infof("Check progress %s", strings.TrimPrefix(fmt.Sprintf("%v", statusMap), "map"))
}

func Generate(cfg *config.Config, results *results.ResultsServer, l log.Logger) (int, error) {
	if cfg.Reporting.Format != "json" {
		return config.ErrorExitCode, fmt.Errorf("report format unknown %s", cfg.Reporting.Format)
	}

	checkExclusionDescriptions(cfg, l)

	checkRequiredVariables(cfg, results.Checks, l)

	requested := cfg.Reporting.Severity.Data()

	// Print results when no output file is set
	vs := parseReports(results.Checks, cfg, l)

	// Print summary table
	summaryTable(vs, l)

	var rs string
	for _, s := range config.Severities() {
		sd := s.Data()
		for _, v := range vs {
			if v.Severity.Name == sd.Name && !v.Excluded && v.Severity.Threshold >= requested.Threshold {
				rs = fmt.Sprintf("%s%s", rs, printVulnerability(&v, l))
			}
		}
	}
	if len(rs) > 0 {
		l.Infof("\nVulnerabilities details:\n%s", rs)
	}

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
		str, _ := json.MarshalIndent(slice, "", "    ")
		if outputFile == "-" {
			fmt.Fprint(os.Stdout, string(str))
		} else {
			dir := filepath.Dir(outputFile)
			err := os.MkdirAll(dir, 0o744)
			if err != nil {
				return config.ErrorExitCode, fmt.Errorf("failed to create directory %s: %s", dir, err)
			}
			f, err := os.OpenFile(outputFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0o644)
			if err != nil {
				return config.ErrorExitCode, fmt.Errorf("unable to open report file %s %+v", outputFile, err)
			}
			defer f.Close()
			if _, err := f.Write(str); err != nil {
				return config.ErrorExitCode, fmt.Errorf("unable to write report file %s %+v", outputFile, err)
			}
		}
	}

	// Get max reported score in vulnerabilities
	var maxScore float32 = -1.0
	for _, v := range vs {
		if v.Score > float32(maxScore) && !v.Excluded {
			maxScore = v.Score
		}
	}

	if current := config.FindSeverityByScore(maxScore).Data(); current.Threshold >= requested.Threshold {
		return current.Exit, nil
	}

	return config.SuccessExitCode, nil
}
