package main

import (
	"crypto/rand"
	"fmt"
	"github.com/jessevdk/go-flags"
	"os"
	"os/exec"
	"os/signal"
	"path"
	"path/filepath"
	"strings"
	"strconv"
	"io/ioutil"
	"syscall"
	"time"
	"encoding/base32"
)

// Generate a random id for the container name.
// This name can't be too long as it is used as
// an interface name as well which will explode if 
// is larger than 6 bytes for some reason.
// Clashes are possible here so this checks against
// known container names to ensure it's unique
func randomName() (string, error) {
	for i := 0; i<25; i++ {
		b := make([]byte, 6)
		_, err := rand.Read(b)
		if err != nil {
			return "", err
		}
		s := base32.StdEncoding.EncodeToString(b)
		s = strings.Replace(s, `=`, ``, -1)
		s = strings.Replace(s, `-`, ``, -1)
		s = strings.Replace(s, `_`, ``, -1)
		s = strings.ToLower(s)
		root := path.Join("/var/lib/containers/", s)
		if _, err := os.Stat(root); os.IsNotExist(err) {
			return s, nil
		}
	}
	return "", fmt.Errorf("failed to generate a unique name")
}

// There can only be one Cmd running. This is it.
var cmd = &Cmd{}

// Cmd encapsulates the command and it's options.
type Cmd struct {
	Config  string   `short:"C" long:"config" description:"path to configuration.nix" default:"./configuration.nix"`
	Bind    string   `short:"b" long:"bind" description:"path on host to bind to /app in the container" default:"./"`
	Command string   `short:"c" long:"command" description:"shell commands to execute"`
	Id      string   `long:"name" description:"name to use for the container" default:"random"`
	Verbose bool     `short:"v" description:"show verbose logging"`
	Timeout int      `short:"t" description:"timeout in seconds to wait for container boot" default:"90"`
	Ports   []string `short:"p" long:"port" description:"expose a container port to the host. example '8080:80' allows access to container port 80 via host port 8080"`
	sigint  chan bool
	netenv map[string]string
}

// logging
func (cmd *Cmd) debug(args ...interface{}) {
	if cmd.Verbose {
		fmt.Println(args...)
	}
}

// Setup the container
func (cmd *Cmd) Create(confpath string) (keyPath string, err error) {
	prv, pub, err := cmd.keygen()
	if err != nil {
		return "", err
	}
	module := fmt.Sprintf(`
		imports=[
			%s
		];
		networking.usePredictableInterfaceNames = false;
		networking.firewall.enable = false;
		networking.nameservers = [ "8.8.8.8" ];
		systemd.services.startNotification = {
			description = "Startup Notification";
			wantedBy = [ "multi-user.target" ];
			after = [ "multi-user.target" ];
			script = 
				''
				echo 1 > /var/lib/startup-done
				'';
			serviceConfig = {
				Type = "oneshot";
			};
		};
		services.openssh = {
			enable = true;
			extraConfig =
				''
				useDNS no
				GSSAPIAuthentication no
				'';
		};
		users.extraUsers.root = {
			openssh.authorizedKeys.keyFiles = [ %s ];
		};
		programs.bash.promptInit =
			''
			IP=$(ip -4 -o addr show dev eth0 | awk '{split($4,a,"/");print a[1]}')
			PROMPT_COLOR="1;31m"
			let $UID && PROMPT_COLOR="1;32m"
			PS1="\n\[\033[$PROMPT_COLOR\][$IP:\w]\\$\[\033[0m\] "
			if test "$TERM" = "xterm"; then
				PS1="\[\033]2;$IP:\w\007\]$PS1"
			fi
			'';
		environment.loginShellInit =
			''
			cd /src
			'';
	`, confpath, pub, )
	err = cmd.container(false, "create", cmd.Id, "--config", module)
	if err != nil {
		return "", err
	}
	// read the generated ip addresses
	cmd.netenv, err = cmd.getNetworkEnv()
	if err != nil {
		return "", err
	}
	_, ok := cmd.netenv["HOST_ADDRESS"]
	if !ok {
		return "", fmt.Errorf("no HOST_ADDRESS found for container")
	}
	_, ok = cmd.netenv["LOCAL_ADDRESS"]
	if !ok {
		return "", fmt.Errorf("no LOCAL_ADDRESS found for container")
	}
	return prv, nil
}

// Destroy the container
func (cmd *Cmd) Destroy() error {
	return cmd.container(false, "destroy", cmd.Id)
}

// Run a command in a container
func (cmd *Cmd) Run(args ...string) error {
	args = append([]string{"run", cmd.Id, "--"}, args...)
	return cmd.container(true, args...)
}

// Login as the current
func (cmd *Cmd) Login(key string) error {
	args := []string{
		"-i", key,
		"-o", "StrictHostKeyChecking=no",
		"-o", "UserKnownHostsFile=/dev/null",
		"-o", "BatchMode=yes",
		fmt.Sprintf("root@%s", cmd.netenv["LOCAL_ADDRESS"]),
	}
	return cmd.ssh(args...)
}

// container is a wrapper around nixos-container.
func (cmd *Cmd) container(tty bool, args ...string) error {
	exe, err := exec.LookPath("nixos-container")
	if err != nil {
		return fmt.Errorf("could not find 'nixos-container' command.")
	}
	cmd.debug(exe, args)
	c := exec.Command(exe, args...)
	if tty || cmd.Verbose {
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
		if tty {
			c.Stdin = os.Stdin
		}
	}
	c.Env = os.Environ()
	return c.Run()
}

// generate ssh keypair at /var in the container, returns full paths to keys from the host
func (cmd *Cmd) keygen() (private string, public string, err error) {
	exe, err := exec.LookPath("ssh-keygen")
	if err != nil {
		err = fmt.Errorf("could not find 'ssh-keygen' command.")
		return
	}
	home := path.Join("/var/lib/containers", cmd.Id, "var")
	if err = os.MkdirAll(home, 0755); err != nil {
		err = fmt.Errorf("failed to create home dir in container: %s", err)
		return
	}
	keyPath := path.Join(home, "id_rsa")
	args := []string{ "-t", "rsa", "-N", "", "-f",  keyPath }
	cmd.debug(exe, args)
	c := exec.Command(exe, args...)
	if cmd.Verbose {
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
	}
	c.Env = os.Environ()
	err = c.Run()
	if err != nil {
		return
	}
	return keyPath, keyPath+".pub", nil
}

// wrapper around ssh
func (cmd *Cmd) ssh(args ...string) error {
	exe, err := exec.LookPath("ssh")
	if err != nil {
		return fmt.Errorf("could not find 'ssh' command.")
	}
	cmd.debug(exe, args)
	c := exec.Command(exe, args...)
	c.Stdout = os.Stdout
	c.Stderr = os.Stderr
	c.Stdin = os.Stdin
	c.Env = os.Environ()
	return c.Run()
}

func (cmd *Cmd) getNetworkEnv() (env map[string]string, err error) {
	b, err := ioutil.ReadFile(path.Join("/etc/containers", fmt.Sprintf("%s.conf", cmd.Id)))
	if err != nil {
		return nil, fmt.Errorf("could not find generated network info: %s", err)
	}
	env = make(map[string]string)
	for _, line := range strings.Split(string(b), "\n") {
		line = strings.TrimSpace(line)
		if line == "" {
			continue
		}
		fields := strings.SplitN(line, "=", 2)
		if len(fields) != 2 {
			continue
		}
		env[fields[0]] = fields[1]
	}
	return env, nil
}

// nspawn is a wrapper around systemd-nspawn that mimics what nixos's
// systemd service does only tweaked a bit for a more ephemeral use case
func (cmd *Cmd) nspawn(root, bindpath string) (err error) {
	// check for command
	exe, err := exec.LookPath("systemd-nspawn")
	if err != nil {
		return fmt.Errorf("could not find 'systemd-nspawn' command.")
	}
	// create "done" socket
	cmd.debug("creating socket for ready signal")
	if err = os.MkdirAll(path.Join(root, "/var/lib"), 0755); err != nil {
		return fmt.Errorf("failed to create path in container root for 'startup-done' fifo: %s", err)
	}
	socket := path.Join(root, "/var/lib/startup-done")
	if err = syscall.Mkfifo(socket, 0600); err != nil {
		return fmt.Errorf("could not create 'startup-done' fifo: %s", err)
	}
	// boot
	args := []string{
		"-M", cmd.Id,
		"-D", root,
		//"--uuid", cmd.Id,
		"--link-journal", "auto",
		"--private-network",
		"--network-veth",
		"--bind-ro", "/nix/store",
		"--bind-ro", "/nix/var/nix/db",
		"--bind-ro", "/nix/var/nix/daemon-socket",
		"--bind", fmt.Sprintf("/nix/var/nix/profiles/per-container/%s:/nix/var/nix/profiles", cmd.Id),
		//"--bind", fmt.Sprintf("/nix/var/nix/gcroots/per-container/%s:/nix/var/nix/gcroots", cmd.Id),
		"--bind", fmt.Sprintf("%s:/src", bindpath),
		"--setenv", fmt.Sprintf(`PATH=%s`, os.ExpandEnv("$PATH")),
		"--setenv", fmt.Sprintf(`HOST_ADDRESS=%s`, cmd.netenv["HOST_ADDRESS"]),
		"--setenv", fmt.Sprintf(`LOCAL_ADDRESS=%s`, cmd.netenv["LOCAL_ADDRESS"]),
		"/nix/var/nix/profiles/system/init",
	}
	cmd.debug(exe, args)
	c := exec.Command(exe, args...)
	c.Env = os.Environ()
	// make use of nixos systemd patches
	c.Env = append(c.Env, "EXIT_ON_REBOOT=1", "NOTIFY_SOCKET=")
	if cmd.Verbose {
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
	}
	err = c.Start()
	if err != nil {
		return fmt.Errorf("failed to start container: %s", err)
	}
	// done channel
	wait := make(chan error, 2)
	// monitor nspawn
	go func() {
		err := c.Wait()
		cmd.debug("nspawn exited", err)
		wait <- err
	}()
	// get done signal from boot
	go func() {
		cmd.debug("waiting for ready signal")
		done, err := os.Open(socket)
		if err != nil {
			wait <- fmt.Errorf("failed to open 'startup-done' fifo: %s", err)
			return
		}
		b := make([]byte, 1)
		n, err := done.Read(b)
		if err != nil {
			wait <- fmt.Errorf("failed to read from 'startup-done' fifo: %s", err)
			return
		}
		if n != 1 {
			wait <- fmt.Errorf("invalid read from the 'startup-done' fifo")
			return
		}
		wait <- nil
	}()
	// wait
	select {
	case <-time.After(time.Duration(cmd.Timeout) * time.Second):
		cmd.debug("killing nspawn as it took too long to boot...")
		if err := c.Process.Kill(); err != nil {
			cmd.debug("failed to kill running container: ", err)
		}
		return fmt.Errorf("timeout waiting for container to start")
	case <-cmd.sigint:
		cmd.debug("SIGINT!")
		if err := c.Process.Kill(); err != nil {
			cmd.debug("attempted to kill running container: ", err)
		}
		return fmt.Errorf("user interrupted container boot")
	case err := <-wait:
		if err != nil {
			return err
		}
	}
	// configure network
	if err := cmd.configureContainerNetwork(); err != nil {
		return err
	}
	if err := cmd.configureHostNetwork(); err != nil {
		return err
	}
	return nil
}

func (cmd *Cmd) ip(args ...string) error {
	// check for command
	exe, err := exec.LookPath("ip")
	if err != nil {
		return fmt.Errorf("could not find 'ip' (iproute2) command.")
	}
	c := exec.Command(exe, args...)
	c.Env = os.Environ()
	if cmd.Verbose {
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
	}
	return c.Run()
}

func (cmd *Cmd) nat(a string, rule string) error {
	// check for command
	exe, err := exec.LookPath("iptables")
	if err != nil {
		return fmt.Errorf("could not find 'iptables' command.")
	}
	args := strings.Fields(rule)
	args = append([]string{"-t", "nat", a}, args...)
	c := exec.Command(exe, args...)
	c.Env = os.Environ()
	if cmd.Verbose {
		c.Stdout = os.Stdout
		c.Stderr = os.Stderr
	}
	return c.Run()
}

func (cmd *Cmd) configureContainerNetwork() (err error) {
	err = cmd.Run("ip", "link", "set", "host0", "name", "eth0")
	if err != nil {
		return err
	}
	err = cmd.Run("ip", "link", "set", "dev", "eth0", "up")
	if err != nil {
		return err
	}
	err = cmd.Run("ip", "route", "add", cmd.netenv["HOST_ADDRESS"], "dev", "eth0")
	if err != nil {
		return err
	}
	err = cmd.Run("ip", "route", "add", "default", "via", cmd.netenv["HOST_ADDRESS"])
	if err != nil {
		return err
	}
	err = cmd.Run("ip", "addr", "add", cmd.netenv["LOCAL_ADDRESS"], "dev", "eth0")
	if err != nil {
		return err
	}
	return nil
}

func (cmd *Cmd) configureHostNetwork() (err error) {
	ve := fmt.Sprintf("ve-%s", cmd.Id)
	err = cmd.ip("link", "set", "dev", ve, "up")
	if err != nil {
		return err
	}
	err = cmd.ip("addr", "add", cmd.netenv["HOST_ADDRESS"], "dev", ve)
	if err != nil {
		return err
	}
	err = cmd.ip("route", "add", cmd.netenv["LOCAL_ADDRESS"], "dev", ve)
	if err != nil {
		return err
	}
	return nil
}

// Execute is the main body of the command
func (cmd *Cmd) Execute() error {
	// Validate config path
	confpath, err := filepath.Abs(os.ExpandEnv(cmd.Config))
	if err != nil {
		return fmt.Errorf("invalid configuration file path: %s", err)
	}
	if _, err := os.Stat(confpath); os.IsNotExist(err) {
		return fmt.Errorf("configuration file not found: %s", confpath)
	}
	// Validate binding path
	bindpath, err := filepath.Abs(os.ExpandEnv(cmd.Bind))
	if err != nil {
		return fmt.Errorf("invalid bind path: %s", err)
	}
	// Generate a name to use as the container name
	if cmd.Id == "random" {
		cmd.Id, err = randomName()
		if err != nil {
			return err
		}
	}
	// Create the container root
	root := path.Join("/var/lib/containers", cmd.Id)
	cmd.debug("creating", root)
	if err := os.MkdirAll(root, 0755); err != nil {
		return err
	}
	defer func() {
		cmd.debug("cleaning up", root)
		if err := os.RemoveAll(root); err != nil {
			// There can be a bit of a race condition here so if it fails
			// wait a few seconds and try again
			time.Sleep(2 * time.Second)
			if err := os.RemoveAll(root); err != nil {
				fmt.Fprintf(os.Stderr, "failed to remove %s\n", root)
			}
		}
	}()
	// Create a nixos container
	defer func() {
		cmd.debug("destroying", cmd.Id)
		if err := cmd.Destroy(); err != nil {
			fmt.Fprintf(os.Stderr, "failed to destroy container %s\n", cmd.Id)
		}
	}()
	key, err := cmd.Create(confpath); 
	if err != nil {
		return err
	}
	// Start it
	if err := cmd.nspawn(root, bindpath); err != nil {
		return err
	}
	defer func() {
		cmd.debug("shutting down", cmd.Id)
		if err := cmd.Run("systemctl", "halt"); err != nil {
			fmt.Fprintf(os.Stderr, "container %s failed to shutdown cleanly\n", cmd.Id)
		}
	}()
	// Expose any ports
	for _, p := range cmd.Ports {
		if !strings.Contains(p, ":") {
			return fmt.Errorf("invalid port mapping: %s", p)
		}
		ps := strings.Split(p, ":")
		hostport, err := strconv.ParseInt(ps[0], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid port mapping: %s, %s", p, err)
		}
		containerport, err := strconv.ParseInt(ps[1], 10, 64)
		if err != nil {
			return fmt.Errorf("invalid port mapping: %s, %s", p, err)
		}
		// NAT
		dnat := fmt.Sprintf(`PREROUTING -p tcp --dport %d -j DNAT --to-destination %s:%d`, hostport, cmd.netenv["LOCAL_ADDRESS"], containerport)
		if err := cmd.nat("-A", dnat); err != nil {
			return err
		}
		defer cmd.nat("-D", dnat)
		snat := fmt.Sprintf(`POSTROUTING -o ve-%s -j MASQUERADE`, cmd.Id)
		if err := cmd.nat("-A", snat); err != nil {
			return err
		}
		defer cmd.nat("-D", snat)
	}
	// Run command in it
	if cmd.Command != "" {
		args := strings.Fields(cmd.Command)
		return cmd.Run(args...)
	}
	return cmd.Login(key)
}

// catches SIGINT and forwards it to a channel so that
// nspawn can be shutdown cleanly. Sending a bunch of SIGINTs
// will just forcably interrupt.
func (cmd *Cmd) startSignalHandler() {
	cmd.sigint = make(chan bool)
	c := make(chan os.Signal, 1)
	signal.Notify(c, os.Interrupt)
	go func() {
		<-c
		cmd.sigint <- true
		<-c
		cmd.sigint <- true
		<-c
		cmd.sigint <- true
	}()
}

// Run main command body
func RunCommand() (err error) {
	p := flags.NewParser(cmd, flags.HelpFlag|flags.PassDoubleDash)
	_, err = p.Parse()
	if err != nil {
		return err
	}
	cmd.startSignalHandler()
	return cmd.Execute()
}

// You can guess this one
func main() {
	err := RunCommand()
	if err != nil {
		fmt.Fprintf(os.Stderr, "%s\n", err.Error())
		os.Exit(1)
	}
}
