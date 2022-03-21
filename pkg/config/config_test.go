/*
Copyright 2021 Adevinta
*/

package config

import (
	"testing"
)

func TestFindSeverityByScore(t *testing.T) {
	tests := []struct {
		score    float32
		expected Severity
	}{
		{
			score:    -1.0, // Shouldn't exists
			expected: SeverityInfo,
		},
		{
			score:    0.0,
			expected: SeverityInfo,
		},
		{
			score:    0.05,
			expected: SeverityInfo,
		},
		{
			score:    0.1,
			expected: SeverityLow,
		},
		{
			score:    3.5,
			expected: SeverityLow,
		},
		{
			score:    4.0,
			expected: SeverityMedium,
		},
		{
			score:    7.5,
			expected: SeverityHigh,
		},
		{
			score:    9.5,
			expected: SeverityCritical,
		},
		{
			score:    11.0, // Shouldn't exist
			expected: SeverityCritical,
		},
	}
	for _, s := range Severities() {
		c := s.Data()
		tests = append(tests, []struct {
			score    float32
			expected Severity
		}{
			{ // If equals
				score:    c.Threshold,
				expected: s,
			},
			{ // Or slightly higher
				score:    c.Threshold + 0.05,
				expected: s,
			},
		}...)
	}

	for _, c := range tests {
		if s := FindSeverityByScore(c.score); s != c.expected {
			t.Fatalf(`FindSeverityByScore(%v)==%s expected %s`, c.score, s.Data().Name, c.expected.Data().Name)
		}
	}
}
