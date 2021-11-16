/*
Copyright 2021 Adevinta
*/

package reporting

import (
	"testing"
)

func TestFindSeverity(t *testing.T) {
	for i := range severities {
		sev := severities[i]
		if s, err := FindSeverity(sev.Name); s.Name != sev.Name || err != nil {
			t.Fatalf(`FindSeverity(%s)==%s,nil instead of %s %+v`, sev.Name, sev.Name, s.Name, err)
		}
	}
	if s, err := FindSeverity("XXXXX"); s != nil || err == nil {
		t.Fatalf(`FindSeverity(XXXXX)==nil,error instead of %v %+v`, s, err)
	}
}

func TestFindSeverityByScore(t *testing.T) {
	tests := []struct {
		score    float32
		expected string
	}{
		{
			score:    -1.0, // Shouldn't exists
			expected: "ALL",
		},
		{
			score:    0.0,
			expected: "ALL",
		},
		{
			score:    0.05,
			expected: "ALL",
		},
		{
			score:    0.1,
			expected: "LOW",
		},
		{
			score:    3.5,
			expected: "LOW",
		},
		{
			score:    4.0,
			expected: "MEDIUM",
		},
		{
			score:    7.5,
			expected: "HIGH",
		},
		{
			score:    9.5,
			expected: "CRITICAL",
		},
		{
			score:    11.0, // Shouldn't exist
			expected: "CRITICAL",
		},
	}
	for _, c := range severities {
		tests = append(tests, []struct {
			score    float32
			expected string
		}{
			{ // If equals
				score:    c.Threshold,
				expected: c.Name,
			},
			{ // Or slightly higher
				score:    c.Threshold + 0.05,
				expected: c.Name,
			},
		}...)
	}

	for _, c := range tests {
		if s := FindSeverityByScore(c.score); s.Name != c.expected {
			t.Fatalf(`FindSeverityByScore(%v)==%s expected %s`, c.score, s.Name, c.expected)
		}
	}
}
