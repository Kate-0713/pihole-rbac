// SPDX-FileCopyrightText: 2026 Kate O'Grady
// SPDX-License-Identifier: AGPL-3.0-or-later

// Command e2e-server runs what the Playwright tests in web/e2e need: two fake Pi-holes, plus two copies of the real
// pihole-rbac binary, each on its own throwaway data directory:
//
//   - fresh: a new database with first-run setup still open, for the setup tests;
//   - seeded: setup done, with the users, roles and instances of e2e.NewFixture (one instance points at a port
//     nothing listens on, so it shows as down).
//
// A control address answers GET /state with the URLs, the fresh server's setup token and the fixture, once both
// servers are up; Playwright waits for it before running any test. Everything is removed on exit (SIGINT or
// SIGTERM, or Ctrl+C); after a hard kill, the next run removes what was left.
//
// It runs the binary rather than the server code in-process, so the tests cover what ships: the embedded frontend,
// its CSP hash and the startup path. Build it first with make build / .\build.ps1 build.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"log"
	"net"
	"net/http"
	"os"
	"os/exec"
	"os/signal"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/Kate-0713/pihole-rbac/internal/e2e"
	"github.com/Kate-0713/pihole-rbac/internal/piholeapi/piholetest"
	"github.com/Kate-0713/pihole-rbac/internal/secrets"
)

type state struct {
	Fresh struct {
		URL        string `json:"url"`
		SetupToken string `json:"setup_token"`
	} `json:"fresh"`
	Seeded struct {
		URL     string       `json:"url"`
		Fixture *e2e.Fixture `json:"fixture"`
	} `json:"seeded"`
}

func main() {
	log.SetFlags(0)
	log.SetPrefix("e2e-server: ")
	if err := run(); err != nil {
		log.Fatal(err)
	}
}

func run() error {
	defaultBin := filepath.Join("bin", "pihole-rbac")
	if runtime.GOOS == "windows" {
		defaultBin += ".exe"
	}
	binary := flag.String("binary", defaultBin, "the pihole-rbac binary to run, built with the frontend embedded")
	control := flag.String("control", "127.0.0.1:18080", "address for GET /state")
	freshAddr := flag.String("fresh", "127.0.0.1:18081", "listen address of the server with setup still open")
	seededAddr := flag.String("seeded", "127.0.0.1:18082", "listen address of the seeded server")
	keep := flag.Bool("keep", false, "keep the data directories on exit, and print where they are")
	flag.Parse()

	bin, err := filepath.Abs(*binary)
	if err != nil {
		return err
	}
	if err := checkBinary(bin); err != nil {
		return err
	}

	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()

	// Two working Pi-holes, and an address nothing listens on for one that is down.
	ph1, ph2 := piholetest.Start(e2e.PiholePassword), piholetest.Start(e2e.PiholePassword)
	defer ph1.Close()
	defer ph2.Close()
	fillPihole(ph1)
	down, err := unusedAddr()
	if err != nil {
		return err
	}

	removeLeftovers()
	root, err := os.MkdirTemp("", tempPrefix)
	if err != nil {
		return err
	}
	if *keep {
		log.Printf("data directories are under %s", root)
	} else {
		defer os.RemoveAll(root)
	}
	freshDir, seededDir := filepath.Join(root, "fresh"), filepath.Join(root, "seeded")

	fixture := e2e.NewFixture(ph1.URL, ph2.URL, "http://"+down)
	if err := os.MkdirAll(seededDir, 0o700); err != nil {
		return err
	}
	if err := e2e.Seed(ctx, seededDir, fixture); err != nil {
		return fmt.Errorf("seeding: %w", err)
	}
	if err := os.MkdirAll(freshDir, 0o700); err != nil {
		return err
	}

	passwords := map[string]string{}
	for _, inst := range fixture.Instances {
		passwords[secrets.InstanceVar(inst.EnvName)] = e2e.PiholePassword
	}
	passwords[secrets.InstanceVar(fixture.SpareEnvName)] = e2e.PiholePassword
	freshEnv := appEnv(*freshAddr, freshDir, nil)
	seededEnv := appEnv(*seededAddr, seededDir, passwords)

	// Anything that ends the run: a server exiting, or the control listener failing.
	errc := make(chan error, 3)
	fresh, err := startApp(bin, "fresh", freshEnv, errc)
	if err != nil {
		return err
	}
	defer fresh.stop()
	seeded, err := startApp(bin, "seeded", seededEnv, errc)
	if err != nil {
		return err
	}
	defer seeded.stop()

	var st state
	st.Fresh.URL, st.Seeded.URL, st.Seeded.Fixture = "http://"+*freshAddr, "http://"+*seededAddr, fixture
	for _, u := range []string{st.Fresh.URL, st.Seeded.URL} {
		if err := waitHealthy(ctx, u, errc); err != nil {
			return err
		}
	}
	// The fresh server made and logged a token as it started; asking for another one the way an admin would also
	// checks that command, and replaces the first.
	if st.Fresh.SetupToken, err = printToken(bin, freshEnv); err != nil {
		return err
	}

	mux := http.NewServeMux()
	mux.HandleFunc("GET /state", func(w http.ResponseWriter, _ *http.Request) {
		w.Header().Set("Content-Type", "application/json")
		_ = json.NewEncoder(w).Encode(st)
	})
	ln, err := net.Listen("tcp", *control)
	if err != nil {
		return err
	}
	srv := &http.Server{Handler: mux, ReadHeaderTimeout: 5 * time.Second}
	go func() { errc <- srv.Serve(ln) }()
	log.Printf("ready: state on http://%s/state, fresh server %s, seeded server %s", *control, st.Fresh.URL, st.Seeded.URL)

	select {
	case <-ctx.Done():
		_ = srv.Close()
		return nil
	case err := <-errc:
		_ = srv.Close()
		return err
	}
}

const tempPrefix = "pihole-rbac-e2e-"

// removeLeftovers deletes the data directories of earlier runs that were killed rather than stopped, as Playwright
// does on Windows, which has no interrupt signal for another process. Only one run can hold the fixed ports at a
// time, so none of them is in use.
func removeLeftovers() {
	old, _ := filepath.Glob(filepath.Join(os.TempDir(), tempPrefix+"*"))
	for _, dir := range old {
		if err := os.RemoveAll(dir); err != nil {
			log.Printf("couldn't remove %s from an earlier run: %v", dir, err)
		}
	}
}

// checkBinary refuses a binary built without the frontend, which would only serve a placeholder page.
func checkBinary(bin string) error {
	out, err := exec.Command(bin, "version").Output()
	if err != nil {
		return fmt.Errorf("%s version: %w (build it first: make build or .\\build.ps1 build)", bin, err)
	}
	for _, line := range strings.Split(string(out), "\n") {
		if strings.TrimSpace(line) == "frontend: embedded" {
			return nil
		}
	}
	return fmt.Errorf("%s was built without the frontend; build it with make build or .\\build.ps1 build", bin)
}

// fillPihole gives the first Pi-hole something to list.
func fillPihole(ph *piholetest.Server) {
	kids := ph.AddGroup("kids")
	ph.AddDomain(piholetest.Domain{Domain: "ads.example", Type: "deny", Kind: "exact", Comment: "tracker", Enabled: true, Groups: []int{0}})
	ph.AddDomain(piholetest.Domain{Domain: "games.example", Type: "deny", Kind: "exact", Enabled: true, Groups: []int{kids}})
	ph.AddDomain(piholetest.Domain{Domain: "school.example", Type: "allow", Kind: "exact", Enabled: true, Groups: []int{0, kids}})
	ph.AddClient(piholetest.Client{Client: "10.0.0.0/24", Comment: "lab subnet", Groups: []int{0}})
	ph.AddClient(piholetest.Client{Client: "10.0.1.5", Name: "printer.lan", Groups: []int{kids}})

	// Five queries, newest first, a minute apart and ending a minute ago: two blocked, three answered.
	now := time.Now()
	q := func(i int, domain, ip, name, status, reply, upstream string, replySec float64) piholetest.Query {
		e := piholetest.Query{ID: 5 - i, Time: float64(now.Add(-time.Duration(i+1)*time.Minute).UnixMilli()) / 1000,
			Type: "A", Domain: domain, Status: status, Upstream: upstream}
		e.Client.IP, e.Client.Name = ip, name
		e.Reply.Type, e.Reply.Time = reply, replySec
		return e
	}
	ph.SetQueries([]piholetest.Query{
		q(0, "ads.example", "10.0.1.5", "printer.lan", "GRAVITY", "IP", "", 0.0001),
		q(1, "school.example", "10.0.0.7", "", "FORWARDED", "IP", "9.9.9.9#53", 0.0123),
		q(2, "games.example", "10.0.1.5", "printer.lan", "DENYLIST", "IP", "", 0.0002),
		q(3, "school.example", "10.0.0.8", "", "CACHE", "IP", "", 0.0003),
		q(4, "news.example", "10.0.0.7", "", "FORWARDED", "IP", "9.9.9.9#53", 0.021),
	})
}

// unusedAddr returns a local address nothing listens on: it is taken and released at once.
func unusedAddr() (string, error) {
	ln, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return "", err
	}
	addr := ln.Addr().String()
	return addr, ln.Close()
}

// appEnv is the environment for one server: this process's environment without any PIHOLE_RBAC_ variable (so a
// developer's own settings can't leak in), plus the server's own.
func appEnv(addr, dataDir string, extra map[string]string) []string {
	var env []string
	for _, kv := range os.Environ() {
		if !strings.HasPrefix(strings.ToUpper(kv), "PIHOLE_RBAC_") {
			env = append(env, kv)
		}
	}
	env = append(env,
		"PIHOLE_RBAC_LISTEN="+addr,
		"PIHOLE_RBAC_DATA_DIR="+dataDir,
		"PIHOLE_RBAC_COOKIE_SECURE=false", // plain HTTP on localhost
		"PIHOLE_RBAC_LOG_LEVEL=warn",
	)
	for k, v := range extra {
		env = append(env, k+"="+v)
	}
	return env
}

// app is one running pihole-rbac server.
type app struct {
	name     string
	cmd      *exec.Cmd
	exited   chan struct{} // closed when the process has exited
	stopping chan struct{} // closed by stop, so an exit it caused isn't reported as a failure
}

// startApp starts `pihole-rbac serve`, with its output prefixed by name. An exit that stop didn't ask for is sent to
// errc.
func startApp(bin, name string, env []string, errc chan<- error) (*app, error) {
	cmd := exec.Command(bin, "serve")
	cmd.Env = env
	out, err := cmd.StdoutPipe()
	if err != nil {
		return nil, err
	}
	cmd.Stderr = cmd.Stdout
	if err := cmd.Start(); err != nil {
		return nil, fmt.Errorf("starting the %s server: %w", name, err)
	}
	a := &app{name: name, cmd: cmd, exited: make(chan struct{}), stopping: make(chan struct{})}
	go prefixLines(out, "["+name+"] ")
	go func() {
		err := cmd.Wait()
		close(a.exited)
		select {
		case <-a.stopping:
		default:
			errc <- fmt.Errorf("the %s server exited: %v", name, err)
		}
	}()
	return a, nil
}

func prefixLines(r io.Reader, prefix string) {
	sc := bufio.NewScanner(r)
	for sc.Scan() {
		fmt.Fprintln(os.Stderr, prefix+sc.Text())
	}
}

// stop asks the server to shut down cleanly where the OS allows it, and kills it if it hasn't after five seconds.
// Windows has no interrupt signal for another process, so there it is killed straight away.
func (a *app) stop() {
	close(a.stopping)
	if runtime.GOOS == "windows" || a.cmd.Process.Signal(os.Interrupt) != nil {
		_ = a.cmd.Process.Kill()
	}
	select {
	case <-a.exited:
	case <-time.After(5 * time.Second):
		_ = a.cmd.Process.Kill()
		<-a.exited
	}
}

// waitHealthy polls the server's /healthz for up to 30 seconds, giving up early if a server exits.
func waitHealthy(ctx context.Context, base string, errc <-chan error) error {
	deadline := time.Now().Add(30 * time.Second)
	for time.Now().Before(deadline) {
		res, err := http.Get(base + "/healthz")
		if err == nil {
			res.Body.Close()
			if res.StatusCode == http.StatusOK {
				return nil
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case err := <-errc:
			return err
		case <-time.After(100 * time.Millisecond):
		}
	}
	return fmt.Errorf("%s didn't become healthy within 30 seconds", base)
}

// printToken runs `pihole-rbac setup --print-token` and returns the token from its last line.
func printToken(bin string, env []string) (string, error) {
	cmd := exec.Command(bin, "setup", "--print-token")
	cmd.Env = env
	out, err := cmd.Output()
	if err != nil {
		var ee *exec.ExitError
		if errors.As(err, &ee) {
			return "", fmt.Errorf("setup --print-token: %w: %s", err, ee.Stderr)
		}
		return "", fmt.Errorf("setup --print-token: %w", err)
	}
	line := strings.TrimSpace(string(out))
	i := strings.LastIndex(line, ": ")
	if !strings.HasPrefix(line, "Setup token") || i < 0 {
		return "", fmt.Errorf("setup --print-token printed %q", line)
	}
	return line[i+2:], nil
}
