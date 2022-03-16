// SSH Client Builder
//
// Build ssh clients by building up configuration

package sshbuilder

import (
	"fmt"
	"net"
	"os"

	"golang.org/x/crypto/ssh"
	"golang.org/x/crypto/ssh/agent"
	"golang.org/x/crypto/ssh/knownhosts"
)

// Builder objects are built up through use of With* and
// friends.  These are copied by value during creation so
// each one may be a branching point or be passed to any
// number of Dials.
type Builder struct {
	buildErrors     []error
	ignoringErrors  bool
	username        string
	host            string
	port            int
	hostPort        string
	knownHostsFile  string
	hostKeyCallback ssh.HostKeyCallback
	authMethods     []ssh.AuthMethod
}

//Returns a string representation of the options in the Builder
func (b Builder) String() string {
	return fmt.Sprintf("%#v", b)
}

//Create a new Builder
func New() Builder {
	return Builder{}
}

//Use the default agent as provided by the environment, similarly to
//how ssh would find the agent.
func (b Builder) WithDefaultAgent() Builder {
	agent, err := newAgent()
	if err != nil {
		return b.addError(err)
	}
	b.authMethods = append(b.authMethods, ssh.PublicKeysCallback(agent.Signers))
	return b
}

//Set the username for the connection
func (b Builder) WithUsername(u string) Builder {
	b.username = u
	return b
}

//Set the hostname for the connection
//
//Mutually exclusive with WithHostPort
func (b Builder) WithHost(h string) Builder {
	b.hostPort = ""
	b.host = h
	return b
}

//Set the host:port for the connection
//
//Mutually exclusive with WithHost and WithPort
func (b Builder) WithHostPort(str string) Builder {
	b.host = ""
	b.port = 0
	b.hostPort = str
	return b
}

//Set the port for the connection
//
//Mutually exclusive with WithHostPort
func (b Builder) WithPort(port int) Builder {
	b.hostPort = ""
	b.port = port
	return b
}

//Add a password auth method to the client which provides
//the passed password.
func (b Builder) WithPassword(password string) Builder {
	b.authMethods = append(b.authMethods, ssh.Password(password))
	return b
}

// Add a known hosts file
//
// This will disable ignoring unknown hosts as well for safety.
// If you must also ignore unknown hosts if they haven't been set,
// call IgnoreUnknownHosts(true) after calling AddKnownHostsFile(f).
//
// Mutually exclusive with WithInsecureIgnoreHostKey
func (b Builder) WithKnownHostsFiles(khf ...string) Builder {
	hkc, err := knownhosts.New(khf...)
	if err != nil {
		return b.addError(err)
	}
	b.hostKeyCallback = hkc
	return b
}

//Ignore host keys (insecure!)
//
//Mutually exclusive with WithKnownHostsFiles
func (b Builder) WithInsecureIgnoreHostKey() Builder {
	b.hostKeyCallback = ssh.InsecureIgnoreHostKey()
	return b
}

// get any errors from the build process
func (b Builder) GetErrors() []error {
	return b.buildErrors
}

// get the most recent error from the build process
func (b Builder) GetError() error {
	errors := b.GetErrors()
	if errorCount := len(errors); errorCount > 0 {
		return errors[errorCount-1]
	}
	return nil
}

// Prevent errors from being recorded
func (b Builder) SuspendErrors() Builder {
	b.ignoringErrors = true
	return b
}

// Resume error recording
func (b Builder) ResumeErrors() Builder {
	b.ignoringErrors = false
	return b
}

func (b Builder) addError(err error) Builder {
	if !b.ignoringErrors {
		b.buildErrors = append(b.buildErrors, err)
	}
	return b
}

// Dial the configured builder, returning a *ssh.Client
func (b Builder) Dial() (*ssh.Client, error) {
	if err := b.GetError(); err != nil {
		return nil, err
	}
	config := &ssh.ClientConfig{
		User:            b.username,
		Auth:            b.authMethods,
		HostKeyCallback: b.hostKeyCallback,
	}

	hostPort := b.hostPort
	if hostPort == "" {
		hostPort = fmt.Sprintf("%s:%d", b.host, b.port)
	}
	sshc, err := ssh.Dial("tcp", hostPort, config)
	if err != nil {
		err = fmt.Errorf("Failed to connect: %w", err)
		return nil, err
	}
	return sshc, nil
}

func newAgent() (agent.ExtendedAgent, error) {
	// ssh-agent(1) provides a UNIX socket at $SSH_AUTH_SOCK.
	socket := os.Getenv("SSH_AUTH_SOCK")
	if socket == "" {
		return nil, fmt.Errorf("SSH_AUTH_SOCK was not set.  Please start an ssh-agent and add your key to it.")
	}
	conn, err := net.Dial("unix", socket)
	if err != nil {
		return nil, fmt.Errorf("Failed to open SSH_AUTH_SOCK: %w", err)
	}

	agentClient := agent.NewClient(conn)
	return agentClient, nil
}
