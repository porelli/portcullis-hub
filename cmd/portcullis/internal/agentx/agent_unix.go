//go:build !windows

package agentx

import (
	"net"
	"os"

	"golang.org/x/crypto/ssh/agent"
)

// Open connects to SSH_AUTH_SOCK.
func Open() (agent.ExtendedAgent, func(), error) {
	sock := os.Getenv("SSH_AUTH_SOCK")
	if sock == "" {
		return nil, nil, ErrNoAgent
	}
	c, err := net.Dial("unix", sock)
	if err != nil {
		return nil, nil, ErrNoAgent
	}
	return agent.NewClient(c), func() { c.Close() }, nil
}
