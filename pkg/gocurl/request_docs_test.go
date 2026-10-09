package gocurl

import (
	"context"
	"os"
	"path/filepath"
	"reflect"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"testing"

	"github.com/ameshkov/gocurl/internal/config"
)

func TestEveryRequestFieldIsDocumented(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate test source to find README.md")
	}
	readmePath := filepath.Join(filepath.Dir(sourceFile), "..", "..", "README.md")
	readme, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	documentation := string(readme)

	requestType := reflect.TypeOf(Request{})
	for i := 0; i < requestType.NumField(); i++ {
		field := requestType.Field(i)
		if !strings.Contains(documentation, field.Name) {
			t.Errorf("Request.%s is missing from README.md", field.Name)
		}
	}
}

func TestRequestFieldContractTableCoversEveryField(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate test source to find README.md")
	}
	readmePath := filepath.Join(filepath.Dir(sourceFile), "..", "..", "README.md")
	readme, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	documentation := string(readme)
	const heading = "### Request field contract"
	start := strings.Index(documentation, heading)
	if start < 0 {
		t.Fatalf("README.md does not contain %q", heading)
	}
	end := strings.Index(documentation[start+len(heading):], "\n### ")
	if end < 0 {
		end = len(documentation) - start - len(heading)
	}
	table := documentation[start+len(heading) : start+len(heading)+end]

	fieldRows, documentedTests := parseRequestContractRows(t, table)

	requestType := reflect.TypeOf(Request{})
	var missing, unknown []string
	for i := 0; i < requestType.NumField(); i++ {
		name := requestType.Field(i).Name
		if _, exists := fieldRows[name]; !exists {
			missing = append(missing, name)
		}
	}
	for name := range fieldRows {
		if _, exists := requestType.FieldByName(name); !exists {
			unknown = append(unknown, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(unknown)
	if len(missing) != 0 || len(unknown) != 0 {
		t.Errorf("README Request contract does not match Request struct: missing=%v unknown=%v", missing, unknown)
	}

	assertRequestContractTestsExist(t, sourceFile, documentedTests)
}

func TestClientDoRejectsMissingURLBeforeNetwork(t *testing.T) {
	result, err := NewClient().Do(context.Background(), Request{})
	if result != nil {
		_ = result.Close()
		t.Fatal("Do(Request{}) returned a result without a URL")
	}
	if err == nil || !strings.Contains(err.Error(), "URL is required") {
		t.Fatalf("Do(Request{}) error = %v, want required URL error", err)
	}
}

func TestReadmeLongOptionSetMatchesCLIOptions(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate test source to find README.md")
	}
	readmePath := filepath.Join(filepath.Dir(sourceFile), "..", "..", "README.md")
	readme, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	documentation := string(readme)
	const heading = "## All command-line arguments"
	headingIndex := strings.Index(documentation, heading)
	if headingIndex < 0 {
		t.Fatalf("README.md does not contain %q", heading)
	}
	codeStart := strings.Index(documentation[headingIndex:], "```shell")
	if codeStart < 0 {
		t.Fatal("README.md CLI help code block is missing")
	}
	codeStart += headingIndex + len("```shell")
	codeEnd := strings.Index(documentation[codeStart:], "```")
	if codeEnd < 0 {
		t.Fatal("README.md CLI help code block is not closed")
	}
	helpBlock := documentation[codeStart : codeStart+codeEnd]
	optionLine := regexp.MustCompile(`(?m)^ {0,8}(?:-[A-Za-z0-9], +)?--([A-Za-z0-9.-]+)(?:[=<\s]|$)`)
	documented := make(map[string]struct{})
	for _, match := range optionLine.FindAllStringSubmatch(helpBlock, -1) {
		documented[match[1]] = struct{}{}
	}

	optionsType := reflect.TypeOf(config.Options{})
	configured := make(map[string]struct{})
	for i := 0; i < optionsType.NumField(); i++ {
		if name := optionsType.Field(i).Tag.Get("long"); name != "" {
			configured[name] = struct{}{}
		}
	}
	var missing, undocumented []string
	for name := range configured {
		if _, ok := documented[name]; !ok {
			missing = append(missing, name)
		}
	}
	for name := range documented {
		if _, ok := configured[name]; !ok && name != "help" {
			undocumented = append(undocumented, name)
		}
	}
	sort.Strings(missing)
	sort.Strings(undocumented)
	if len(missing) != 0 || len(undocumented) != 0 {
		t.Errorf("README CLI options differ from config.Options: missing=%v undocumented=%v", missing, undocumented)
	}
}

func TestReadmeLongOptionDescriptionsMatchCLIOptions(t *testing.T) {
	_, sourceFile, _, ok := runtime.Caller(0)
	if !ok {
		t.Fatal("could not locate test source to find README.md")
	}
	readmePath := filepath.Join(filepath.Dir(sourceFile), "..", "..", "README.md")
	readme, err := os.ReadFile(readmePath)
	if err != nil {
		t.Fatalf("read README.md: %v", err)
	}
	documentation := string(readme)
	const heading = "## All command-line arguments"
	headingIndex := strings.Index(documentation, heading)
	if headingIndex < 0 {
		t.Fatalf("README.md does not contain %q", heading)
	}
	codeStart := strings.Index(documentation[headingIndex:], "```shell")
	if codeStart < 0 {
		t.Fatal("README.md CLI help code block is missing")
	}
	codeStart += headingIndex + len("```shell")
	codeEnd := strings.Index(documentation[codeStart:], "```")
	if codeEnd < 0 {
		t.Fatal("README.md CLI help code block is not closed")
	}
	lines := strings.Split(documentation[codeStart:codeStart+codeEnd], "\n")
	optionLine := regexp.MustCompile(
		`^\s*(?:-[A-Za-z0-9],\s*)?--([A-Za-z0-9][A-Za-z0-9.-]*)(?:=(?:<[^>]*>|[^\s]*))?\s{2,}(.+?)\s*$`,
	)
	type documentedOption struct {
		name  string
		start int
	}
	var options []documentedOption
	for i, line := range lines {
		if match := optionLine.FindStringSubmatch(line); match != nil {
			options = append(options, documentedOption{name: match[1], start: i})
		}
	}
	documentedDescriptions := make(map[string]string, len(options))
	for i, option := range options {
		end := len(lines)
		if i+1 < len(options) {
			end = options[i+1].start
		}
		documentedDescriptions[option.name] = strings.Join(lines[option.start:end], " ")
	}

	optionsType := reflect.TypeOf(config.Options{})
	var mismatches []string
	for i := 0; i < optionsType.NumField(); i++ {
		field := optionsType.Field(i)
		name := field.Tag.Get("long")
		description := strings.TrimSpace(field.Tag.Get("description"))
		if name == "" || description == "" {
			continue
		}
		documented, exists := documentedDescriptions[name]
		if !exists {
			mismatches = append(mismatches, "--"+name+" is missing")
			continue
		}
		normalize := func(value string) string {
			return strings.Join(strings.Fields(strings.ToLower(value)), " ")
		}
		if !strings.Contains(normalize(documented), normalize(description)) {
			mismatches = append(
				mismatches,
				"--"+name+" description differs (CLI: "+description+"; README: "+strings.TrimSpace(documented)+")",
			)
		}
	}
	sort.Strings(mismatches)
	if len(mismatches) != 0 {
		t.Errorf("README CLI descriptions differ from config.Options: %s", strings.Join(mismatches, "; "))
	}
}

func parseRequestContractRows(t *testing.T, table string) (map[string]struct{}, map[string]struct{}) {
	t.Helper()
	fieldRows := make(map[string]struct{})
	documentedTests := make(map[string]struct{})
	testReference := regexp.MustCompile("`(Test[A-Za-z0-9_]+)`")
	for _, line := range strings.Split(table, "\n") {
		line = strings.TrimSpace(line)
		if !strings.HasPrefix(line, "| `Request.") {
			continue
		}
		cells := strings.Split(line, "|")
		if len(cells) != 6 {
			t.Errorf("Request contract row must have four columns: %q", line)
			continue
		}
		field := strings.TrimSuffix(strings.TrimPrefix(strings.TrimSpace(cells[1]), "`Request."), "`")
		if field == "" || strings.TrimSpace(cells[2]) == "" || strings.TrimSpace(cells[3]) == "" ||
			strings.TrimSpace(cells[4]) == "" {
			t.Errorf("Request contract row has an empty field, mapping, behavior, or test: %q", line)
			continue
		}
		for _, match := range testReference.FindAllStringSubmatch(cells[4], -1) {
			documentedTests[match[1]] = struct{}{}
		}
		if _, exists := fieldRows[field]; exists {
			t.Errorf("Request.%s appears more than once in the contract table", field)
		}
		fieldRows[field] = struct{}{}
	}

	return fieldRows, documentedTests
}

func assertRequestContractTestsExist(t *testing.T, sourceFile string, documentedTests map[string]struct{}) {
	t.Helper()
	testDefinition := regexp.MustCompile(`(?m)^func (Test[A-Za-z0-9_]+)\(`)
	definedTests := make(map[string]struct{})
	for _, root := range []string{filepath.Join(filepath.Dir(sourceFile), "..", "..", "pkg"), filepath.Join(filepath.Dir(sourceFile), "..", "..", "internal")} {
		walkErr := filepath.WalkDir(root, func(path string, entry os.DirEntry, walkErr error) error {
			if walkErr != nil || entry.IsDir() || !strings.HasSuffix(path, "_test.go") {
				return walkErr
			}
			content, readErr := os.ReadFile(path)
			if readErr != nil {
				return readErr
			}
			for _, match := range testDefinition.FindAllSubmatch(content, -1) {
				definedTests[string(match[1])] = struct{}{}
			}
			return nil
		})
		if walkErr != nil {
			t.Fatalf("scan Go tests under %s: %v", root, walkErr)
		}
	}
	var staleTests []string
	for name := range documentedTests {
		if _, exists := definedTests[name]; !exists {
			staleTests = append(staleTests, name)
		}
	}
	sort.Strings(staleTests)
	if len(staleTests) != 0 {
		t.Errorf("README Request contract references missing tests: %v", staleTests)
	}
}
