package testutil

import (
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"slices"
	"strings"
	"testing"

	"gopkg.in/yaml.v3"
)

type qualityWorkflow struct {
	On   map[string]yaml.Node  `yaml:"on"`
	Jobs map[string]qualityJob `yaml:"jobs"`
}

type qualityJob struct {
	Needs    []string `yaml:"needs"`
	Strategy struct {
		FailFast *bool `yaml:"fail-fast"`
		Matrix   struct {
			OS []string `yaml:"os"`
		} `yaml:"matrix"`
	} `yaml:"strategy"`
	Steps []qualityStep `yaml:"steps"`
}

type qualityStep struct {
	Name            string            `yaml:"name"`
	Uses            string            `yaml:"uses"`
	Run             string            `yaml:"run"`
	If              string            `yaml:"if"`
	ContinueOnError bool              `yaml:"continue-on-error"`
	With            map[string]string `yaml:"with"`
}

func TestQualityGateContractsStayAligned(t *testing.T) {
	workflow, makefile, script := loadQualityGateContracts(t)
	if problems := qualityGateProblems(workflow, makefile, script); len(problems) != 0 {
		t.Fatalf("quality gate drift: %v", problems)
	}
}

func TestQualityGateContractRejectsMissingOrOptionalChecks(t *testing.T) {
	for _, tc := range []struct {
		name   string
		mutate func(*qualityWorkflow)
	}{
		{"missing-lint", func(w *qualityWorkflow) { removeQualityStep(w, "Lint Go packages") }},
		{"missing-markdown", func(w *qualityWorkflow) { removeQualityStep(w, "Lint Markdown") }},
		{"missing-plain-tests", func(w *qualityWorkflow) { removeQualityStep(w, "Run tests without race instrumentation") }},
		{"missing-vendored-wire", func(w *qualityWorkflow) { removeQualityStep(w, "Run vendored QUIC transport-parameter wire tests") }},
		{"optional-lint", func(w *qualityWorkflow) {
			changeQualityStep(w, "Lint Go packages", func(s *qualityStep) { s.ContinueOnError = true })
		}},
		{"linux-only-lint", func(w *qualityWorkflow) {
			changeQualityStep(w, "Lint Go packages", func(s *qualityStep) { s.If = "matrix.os == 'ubuntu-latest'" })
		}},
		{"no-release-gate", func(w *qualityWorkflow) { job := w.Jobs["build"]; job.Needs = nil; w.Jobs["build"] = job }},
		{"fail-fast", func(w *qualityWorkflow) {
			job := w.Jobs["tests"]
			yes := true
			job.Strategy.FailFast = &yes
			w.Jobs["tests"] = job
		}},
		{"fixed-go-version", func(w *qualityWorkflow) {
			changeQualityStep(w, "", func(s *qualityStep) {
				if strings.HasPrefix(s.Uses, "actions/setup-go@") {
					s.With = map[string]string{"go-version": "1.26.5"}
				}
			})
		}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			workflow, makefile, script := loadQualityGateContracts(t)
			tc.mutate(&workflow)
			if len(qualityGateProblems(workflow, makefile, script)) == 0 {
				t.Fatal("accepted a broken quality gate")
			}
		})
	}
}

func loadQualityGateContracts(t *testing.T) (qualityWorkflow, string, string) {
	t.Helper()
	_, source, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("cannot locate repository")
	}
	root := filepath.Join(filepath.Dir(source), "..", "..")
	read := func(path string) []byte {
		data, err := os.ReadFile(filepath.Join(root, path))
		if err != nil {
			t.Fatal(err)
		}
		return data
	}
	var workflow qualityWorkflow
	if err := yaml.Unmarshal(read(".github/workflows/build.yaml"), &workflow); err != nil {
		t.Fatal(err)
	}
	return workflow, string(read("Makefile")), string(read("scripts/check.ps1"))
}

func qualityGateProblems(workflow qualityWorkflow, makefile, script string) []string {
	problems := qualityMatrixProblems(workflow)
	steps := workflow.Jobs["tests"].Steps
	for _, requirement := range []struct{ name, command string }{
		{"Verify modules", "mod verify"},
		{"Vet packages", "vet -mod=vendor ./..."},
		{"Run tests without race instrumentation", "test -count=1 -mod=vendor ./..."},
		{"Build all packages", "build -mod=vendor ./..."},
	} {
		step, exists := findQualityStep(steps, requirement.name)
		if !exists || !strings.Contains(step.Run, "go "+requirement.command) ||
			step.If != "" || step.ContinueOnError ||
			!strings.Contains(
				makefile,
				"go "+requirement.command,
			) || !strings.Contains(script, "$selectedGo "+requirement.command) {
			problems = append(problems, "missing mandatory shared command: "+requirement.name)
		}
	}
	problems = append(problems, qualityRaceAndWireProblems(steps, makefile, script)...)
	problems = append(problems, qualityLintProblems(steps, makefile, script)...)
	if !strings.Contains(script, "[IO.Path]::PathSeparator") {
		problems = append(problems, "PowerShell PATH is not platform-dependent")
	}
	clean, exists := findQualityStep(steps, "Verify clean checkout")
	if !exists || !strings.Contains(clean.Run, "--untracked-files=all") || clean.If != "" || clean.ContinueOnError {
		problems = append(problems, "missing mandatory clean checkout check")
	}
	return problems
}

func qualityMatrixProblems(workflow qualityWorkflow) []string {
	var problems []string
	job := workflow.Jobs["tests"]
	if job.Strategy.FailFast == nil || *job.Strategy.FailFast {
		problems = append(problems, "matrix must not cancel other diagnostics on first failure")
	}
	for _, os := range []string{"windows-latest", "ubuntu-latest", "macos-latest"} {
		if !slices.Contains(job.Strategy.Matrix.OS, os) {
			problems = append(problems, "missing configured platform: "+os)
		}
	}
	if !slices.Contains(workflow.Jobs["build"].Needs, "tests") {
		problems = append(problems, "release build bypasses quality gate")
	}
	for _, name := range []string{"tests", "build"} {
		for _, step := range workflow.Jobs[name].Steps {
			if strings.HasPrefix(step.Uses, "actions/setup-go@") && step.With["go-version-file"] != "go.mod" {
				problems = append(problems, "Go version must come from go.mod in "+name)
			}
		}
	}
	return problems
}

func qualityRaceAndWireProblems(steps []qualityStep, makefile, script string) []string {
	var problems []string
	for _, name := range []string{"Run tests", "Run vendored QUIC transport-parameter wire tests"} {
		step, exists := findQualityStep(steps, name)
		if !exists || step.If != "" || step.ContinueOnError {
			problems = append(problems, "missing mandatory test step: "+name)
			continue
		}
		for _, required := range []string{"-race", "-count=1", "-mod=vendor"} {
			if !strings.Contains(step.Run, required) {
				problems = append(problems, name+" missing "+required)
			}
		}
		marker := "-bench=."
		if name != "Run tests" {
			marker = "TransportParametersMarshalPreservesExplicitZeroValues"
		}
		if !strings.Contains(step.Run, marker) || !strings.Contains(makefile, marker) ||
			!strings.Contains(script, marker) {
			problems = append(problems, name+" does not match local gate")
		}
	}
	return problems
}

func qualityLintProblems(steps []qualityStep, makefile, script string) []string {
	var problems []string
	for _, name := range []string{"Lint Go packages", "Lint Markdown"} {
		step, exists := findQualityStep(steps, name)
		if !exists || step.If != "" || step.ContinueOnError {
			problems = append(problems, "missing mandatory lint: "+name)
			continue
		}
		if name == "Lint Go packages" {
			if !strings.HasPrefix(step.Uses, "golangci/golangci-lint-action@") || step.With["version"] != "v2.10.1" ||
				step.With["args"] != "--modules-download-mode=vendor" {
				problems = append(problems, "wrong Go lint configuration")
			}
		} else if !strings.Contains(step.Run, "npx --no-install markdownlint-cli .") {
			problems = append(problems, "wrong Markdown lint command")
		}
	}
	for _, marker := range []string{"markdownlint-cli .", "--modules-download-mode=vendor"} {
		if !strings.Contains(makefile, marker) || !strings.Contains(script, marker) {
			problems = append(problems, fmt.Sprintf("missing local lint marker %q", marker))
		}
	}
	return problems
}

func findQualityStep(steps []qualityStep, name string) (qualityStep, bool) {
	for _, step := range steps {
		if step.Name == name {
			return step, true
		}
	}
	return qualityStep{}, false
}

func removeQualityStep(w *qualityWorkflow, name string) {
	job := w.Jobs["tests"]
	job.Steps = slices.DeleteFunc(job.Steps, func(s qualityStep) bool { return s.Name == name })
	w.Jobs["tests"] = job
}

func changeQualityStep(w *qualityWorkflow, name string, change func(*qualityStep)) {
	job := w.Jobs["tests"]
	for i := range job.Steps {
		if job.Steps[i].Name == name {
			change(&job.Steps[i])
		}
	}
	w.Jobs["tests"] = job
}
