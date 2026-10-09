package config

import (
	"bytes"
	"reflect"
	"strings"
	"testing"

	goFlags "github.com/jessevdk/go-flags"
)

func TestRenderedHelpIncludesEveryLongOptionAndDescription(t *testing.T) {
	var output bytes.Buffer
	parser := goFlags.NewParser(&Options{}, goFlags.Default)
	parser.WriteHelp(&output)
	renderedHelp := strings.Join(strings.Fields(output.String()), " ")
	help := normalizeHelpText(renderedHelp)
	if renderedHelp == "" {
		t.Fatal("rendered CLI help is empty")
	}

	optionsType := reflect.TypeOf(Options{})
	for i := 0; i < optionsType.NumField(); i++ {
		field := optionsType.Field(i)
		longName := field.Tag.Get("long")
		if longName == "" {
			continue
		}
		if !strings.Contains(renderedHelp, longName) {
			t.Errorf("rendered help does not contain --%s", longName)
		}
		words := strings.Fields(field.Tag.Get("description"))
		if len(words) > 2 {
			words = words[:2]
		}
		if len(words) != 0 {
			descriptionPrefix := normalizeHelpText(strings.Join(words, " "))
			if !strings.Contains(help, descriptionPrefix) {
				t.Errorf(
					"rendered help does not contain the description prefix for --%s: %q",
					longName,
					descriptionPrefix,
				)
			}
		}
	}
}

func normalizeHelpText(value string) string {
	// go-flags may hyphenate long words at terminal-width boundaries.
	flattened := strings.Join(strings.Fields(value), " ")
	flattened = strings.ReplaceAll(flattened, "- ", "")
	return strings.ReplaceAll(flattened, "-", "")
}
