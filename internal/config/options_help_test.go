package config

import (
	"reflect"
	"strings"
	"testing"
)

func TestEveryLongOptionHasHelpDescription(t *testing.T) {
	optionsType := reflect.TypeOf(Options{})
	longOptions := 0
	for i := 0; i < optionsType.NumField(); i++ {
		field := optionsType.Field(i)
		longName := field.Tag.Get("long")
		if longName == "" {
			continue
		}
		longOptions++
		if description := strings.TrimSpace(field.Tag.Get("description")); description == "" {
			t.Errorf("--%s has no help description", longName)
		}
	}
	if longOptions == 0 {
		t.Fatal("Options has no long options; test is no longer checking the CLI")
	}
}
