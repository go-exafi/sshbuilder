package sshbuilder

import (
	"testing"

	"github.com/go-exafi/dockertesting"
)

func TestSudoRun(t *testing.T) {
	resource := dockertesting.RunDockerfile(t, "test/Dockerfile")
	resource.Expire(300)

	sshb := New().
		WithUsername("testuser").
		WithHostPort(resource.GetHostPort("22/tcp")).
		WithInsecureIgnoreHostKey().
		WithPassword("pass word")

	sshc, err := sshb.Dial()
	if err != nil {
		t.Errorf("Failed to dial: %v", sshb)
	}
	_ = sshc
}
