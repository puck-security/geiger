package dbrecon

import (
	"context"
	"testing"
	"time"
)

func TestMongoSupported(t *testing.T) {
	if !Supported("mongodb://h/db") || !Supported("mongodb+srv://h/db") {
		t.Error("mongodb schemes should be Supported")
	}
}

func TestMongoFailsFastWhenUnreachable(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Second)
	defer cancel()
	start := time.Now()
	if _, err := reconMongo(ctx, "mongodb://127.0.0.1:1/db"); err == nil {
		t.Error("expected a connection error to an unreachable mongo")
	}
	if time.Since(start) > 5*time.Second {
		t.Errorf("recon should fail fast, took %s", time.Since(start))
	}
}
