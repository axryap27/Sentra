package sarif

import (
	"encoding/json"
	"testing"

	"sentra-analyzer/internal/engine"
)

func TestLog(t *testing.T) {
	log := Log(map[string][]engine.Finding{
		"/repo/src/a.py": {{Line: 3, Column: 5, EndLine: 3, EndColumn: 20, Rule: "sql_injection", CWE: "CWE-89", Severity: "High", Issue: "SQL injection"}},
	}, "/repo")
	b, _ := json.Marshal(log)
	var v struct {
		Version string `json:"version"`
		Runs    []struct {
			Tool struct {
				Driver struct {
					Rules []struct{ ID string } `json:"rules"`
				} `json:"driver"`
			} `json:"tool"`
			Results []struct {
				RuleID    string `json:"ruleId"`
				RuleIndex int    `json:"ruleIndex"`
				Level     string `json:"level"`
				Locations []struct {
					PhysicalLocation struct {
						ArtifactLocation struct{ URI string } `json:"artifactLocation"`
					} `json:"physicalLocation"`
				} `json:"locations"`
			} `json:"results"`
		} `json:"runs"`
	}
	if err := json.Unmarshal(b, &v); err != nil {
		t.Fatal(err)
	}
	r := v.Runs[0].Results[0]
	if v.Version != "2.1.0" || r.Level != "error" || r.Locations[0].PhysicalLocation.ArtifactLocation.URI != "src/a.py" {
		t.Errorf("unexpected SARIF: %s", b)
	}
	if v.Runs[0].Tool.Driver.Rules[r.RuleIndex].ID != r.RuleID {
		t.Errorf("ruleIndex %d does not point at %s", r.RuleIndex, r.RuleID)
	}
}
