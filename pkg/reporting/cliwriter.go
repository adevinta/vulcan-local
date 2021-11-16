/*
Copyright 2021 Adevinta
*/

package reporting

import (
	"bytes"
	"fmt"
	"sort"
	"strings"

	"github.com/adevinta/vulcan-agent/log"
	report "github.com/adevinta/vulcan-report"
)

const (
	SummaryWidth   = 30
	Width          = 100
	baseIndent     = 2
	resourcesLimit = 3
)

// Create a new extended entity to allow to filter by all the fields
type ExtendedVulnerability struct {
	*report.CheckData
	*report.Vulnerability
	Severity *Severity
	Excluded bool
}

func summaryTable(s []ExtendedVulnerability, l log.Logger) {
	if len(s) == 0 {
		l.Infof("No vulnerabilities found during the last scan")
		return
	}
	data := make(map[string]int)
	excluded := 0
	for _, v := range s {
		if v.Excluded {
			excluded++
		} else {
			data[FindSeverityByScore(v.Score).Name]++
		}
	}
	buf := new(bytes.Buffer)
	fmt.Fprint(buf, "\nSummary of the last scan:\n")
	for _, d := range severities {
		color := 0
		if data[d.Name] != 0 {
			color = d.Color
		}
		fmt.Fprintf(buf, "%s%s%s%4d\n", indentate(baseIndent), formatString(d.Name, color), strings.Repeat("·", SummaryWidth-len(d.Name)), data[d.Name])
	}
	if excluded > 0 {
		fmt.Fprintf(buf, "\nNumber of excluded vulnerabilities: %d\n", excluded)
	}
	fmt.Fprint(buf, "\n")
	l.Infof(buf.String())
}

func printVulnerability(v *ExtendedVulnerability, l log.Logger) string {
	severity := v.Severity.Name
	color := v.Severity.Color
	if severity == "NONE" {
		color = 0
		severity = "INFORMATIONAL"
	}
	buf := new(bytes.Buffer)
	fmt.Fprint(buf, formatString(strings.Repeat("=", Width), color))
	n := (Width - len(severity)) / 2
	fmt.Fprint(buf, formatString(fmt.Sprintf("\n%s%s%s\n", strings.Repeat("=", n), severity, strings.Repeat("=", Width-n-len(severity))), color))
	fmt.Fprintf(buf, "%s %s\n", formatString("TARGET:", 0), v.Target)
	affectedResource := v.Vulnerability.AffectedResourceString
	if affectedResource == "" {
		affectedResource = v.Vulnerability.AffectedResource
	}
	if affectedResource != "" {
		fmt.Fprintf(buf, "%s %s\n", formatString("AFFECTED RESOURCE:", 0), affectedResource)
	}
	fmt.Fprintf(buf, "%s %s\n", formatString("SUMMARY:", 0), v.Vulnerability.Summary)
	dlines := splitLines(v.Vulnerability.Description, baseIndent, Width)
	fmt.Fprintf(buf, "\n%s\n%s%s", formatString("DESCRIPTION:", 0), indentate(baseIndent), strings.Join(dlines, "\n"+indentate(baseIndent)))
	if len(v.Vulnerability.Details) != 0 {
		dlines = splitLines(v.Vulnerability.Details, baseIndent, Width)
		fmt.Fprintf(buf, "\n\n%s\n%s%s", formatString("DETAILS:", 0), indentate(baseIndent), strings.Join(dlines, "\n"+indentate(baseIndent)))
	}
	if len(v.Vulnerability.References) != 0 && v.Vulnerability.References[0] != "" {
		sep := "\n" + indentate(baseIndent) + "- "
		fmt.Fprintf(buf, "\n\n%s%s%s", formatString("REFERENCES:", 0), sep, strings.Join(v.Vulnerability.References, sep))
	}
	if len(v.Vulnerability.Resources) != 0 {
		for _, r := range v.Vulnerability.Resources {
			if len(r.Rows) != 0 {
				fmt.Fprintf(buf, "\n\n%s", formatString(r.Name+":", 0))
				count := 0
				for _, rs := range r.Rows {
					ks := make([]string, 0, len(rs))
					for k := range rs {
						ks = append(ks, k)
					}
					sort.Strings(ks)
					for _, k := range ks {
						if len(rs[k]) != 0 {
							ts := splitLines(rs[k], baseIndent, Width-baseIndent-len(k)-2)
							fmt.Fprintf(buf, "\n%s%s: %s", indentate(baseIndent), formatString(k, 0), strings.Join(ts, "\n"+indentate(baseIndent+len(k)+2)))
						}
					}
					fmt.Fprint(buf, "\n")
					count++
					if count == resourcesLimit {
						message := fmt.Sprintf("And %d more references", len(rs)-resourcesLimit)
						fmt.Fprintf(buf, "%s%s\n%s%s", indentate((Width+baseIndent)/2-2), "···", indentate((Width+baseIndent-len(message))/2), message)
						break
					}
				}
			}
		}
	}
	fmt.Fprintf(buf, "\n\n")
	return buf.String()
}

func splitLines(s string, indent int, width int) []string {
	var lines []string
	for pointer := 0; pointer < len(s); {
		if s[pointer:pointer+1] == " " || s[pointer:pointer+1] == "\n" {
			pointer++
		}
		npointer := pointer + width - indent
		if npointer > len(s) {
			npointer = len(s)
		} else if npointer-pointer+indent <= width {
			npointer = pointer + findLastSpace(s[pointer:npointer])
		}
		line := strings.ReplaceAll(string(s[pointer:npointer]), "\n", "\n"+indentate(indent))
		lines = append(lines, line)
		pointer = npointer
	}
	return lines
}

func findLastSpace(line string) int {
	nl := strings.Index(line, "\n")
	p := strings.LastIndex(line, " ")
	if nl != -1 {
		return nl
	}
	if p == -1 {
		return len(line)
	}
	return p
}

func formatString(s string, i int) string {
	if i == 0 {
		return fmt.Sprintf("\x1b[1m%s\x1b[0m", s)
	}
	return fmt.Sprintf("\x1b[%d;1m%s\x1b[0m", i, s)
}

func indentate(indent int) string {
	i := strings.Repeat(" ", indent)
	return i
}
