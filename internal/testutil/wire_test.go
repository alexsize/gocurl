package testutil

import (
	"strconv"
	"testing"
)

func TestUint16Bounds(t *testing.T) {
	for _, value := range []int{0, 1, 65535} {
		if int(Uint16(value)) != value {
			t.Fatalf("Uint16(%d) changed the value", value)
		}
	}
	for _, value := range []int{-1, 65536} {
		t.Run(strconv.Itoa(value), func(t *testing.T) {
			assertFixturePanic(t, func() { _ = Uint16(value) })
		})
	}
}

func TestUint8Bounds(t *testing.T) {
	for _, value := range []int{0, 1, 255} {
		if int(Uint8(value)) != value {
			t.Fatalf("Uint8(%d) changed the value", value)
		}
	}
	for _, value := range []int{-1, 256} {
		t.Run(strconv.Itoa(value), func(t *testing.T) {
			assertFixturePanic(t, func() { _ = Uint8(value) })
		})
	}
}

func assertFixturePanic(t *testing.T, encode func()) {
	t.Helper()
	defer func() {
		if recover() == nil {
			t.Fatal("out-of-range fixture value was silently encoded")
		}
	}()
	encode()
}
