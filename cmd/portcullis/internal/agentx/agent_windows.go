//go:build windows

package agentx

import (
	"time"

	"github.com/Microsoft/go-winio"
	"golang.org/x/crypto/ssh/agent"
)

// PipeName is the Windows OpenSSH agent's named pipe.
const PipeName = `\\.\pipe\openssh-ssh-agent`

// Open connects to the Windows OpenSSH agent.
func Open() (agent.ExtendedAgent, func(), error) {
	timeout := 3 * time.Second
	c, err := winio.DialPipe(PipeName, &timeout)
	if err != nil {
		return nil, nil, ErrNoAgent
	}
	return agent.NewClient(c), func() { c.Close() }, nil
}
