// Command op-sidecar exposes the 1Password Go SDK to the Tauri backend.
//
// It exists because 1Password ships no Rust SDK: the Tauri backend talks to
// this binary instead of to 1Password directly. Authentication uses the
// desktop app integration, so every user authorizes with their own account
// and no shared token has to be distributed.
//
// The process is long-lived and speaks newline-delimited JSON: one request
// object per line on stdin, one response object per line on stdout. It has to
// stay resident because building the SDK client costs about 4.5s (compiling
// the WASM core plus the authorization handshake), while individual calls
// take 170-400ms. Spawning per request would pay that 4.5s every time.
//
//	-> {"id":1,"cmd":"resolve","ref":"op://vault/item/field"}
//	<- {"id":1,"ok":true,"data":"hunter2"}
//	<- {"id":1,"ok":false,"error":"..."}
//
// The client is built on the first request rather than at startup, so app
// launch stays fast and the 1Password authorization prompt appears only once
// the user actually asks for a secret.
//
// Diagnostics go to stderr; stdout carries nothing but responses.
package main

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	onepassword "github.com/1password/onepassword-sdk-go"
)

const (
	integrationName    = "WireTerm"
	integrationVersion = "v0.1.0"
	callTimeout        = 60 * time.Second
	// Responses stay well under this; the limit only guards against a
	// malformed stdin stream growing the buffer without bound.
	maxLineBytes = 1 << 20
)

type request struct {
	ID    uint64 `json:"id"`
	Cmd   string `json:"cmd"`
	Ref   string `json:"ref,omitempty"`
	Vault string `json:"vault,omitempty"`
	Item  string `json:"item,omitempty"`
}

type response struct {
	ID    uint64 `json:"id"`
	OK    bool   `json:"ok"`
	Data  any    `json:"data,omitempty"`
	Error string `json:"error,omitempty"`
}

type vault struct {
	ID        string `json:"id"`
	Title     string `json:"title"`
	ItemCount uint32 `json:"itemCount"`
}

type item struct {
	ID       string `json:"id"`
	Title    string `json:"title"`
	Category string `json:"category"`
}

// field describes one field of an item. The value is deliberately reduced to
// its length: this command exists to find out what an item is called and how
// it is shaped, not to hand out secrets. Use "resolve" to read a value.
type field struct {
	ID          string `json:"id"`
	Title       string `json:"title"`
	SectionID   string `json:"sectionId,omitempty"`
	FieldType   string `json:"fieldType"`
	ValueLength int    `json:"valueLength"`
}

// server holds the SDK client across requests. Requests are handled one at a
// time, so no locking is needed.
type server struct {
	account string
	client  *onepassword.Client
	out     *json.Encoder
}

func main() {
	account := os.Getenv("OP_ACCOUNT")
	if account == "" {
		fmt.Fprintln(os.Stderr, "op-sidecar: OP_ACCOUNT is not set")
		os.Exit(2)
	}

	s := &server{account: account, out: json.NewEncoder(os.Stdout)}

	in := bufio.NewScanner(os.Stdin)
	in.Buffer(make([]byte, 0, 64*1024), maxLineBytes)
	for in.Scan() {
		line := in.Bytes()
		if len(line) == 0 {
			continue
		}
		var req request
		if err := json.Unmarshal(line, &req); err != nil {
			s.reply(response{OK: false, Error: fmt.Sprintf("malformed request: %v", err)})
			continue
		}
		s.handle(req)
	}
	if err := in.Err(); err != nil {
		fmt.Fprintf(os.Stderr, "op-sidecar: reading stdin: %v\n", err)
		os.Exit(1)
	}
	// stdin closed: the backend is gone, so are we.
}

func (s *server) handle(req request) {
	ctx, cancel := context.WithTimeout(context.Background(), callTimeout)
	defer cancel()

	data, err := s.dispatch(ctx, req)
	if err != nil {
		s.reply(response{ID: req.ID, OK: false, Error: err.Error()})
		return
	}
	s.reply(response{ID: req.ID, OK: true, Data: data})
}

func (s *server) dispatch(ctx context.Context, req request) (any, error) {
	if req.Cmd == "ping" {
		return "pong", nil
	}

	return withSession(
		func() (any, error) {
			client, err := s.ensureClient(ctx)
			if err != nil {
				return nil, err
			}
			return s.run(ctx, client, req)
		},
		func() { s.client = nil },
	)
}

// withSession runs call, and once more with a fresh client if 1Password no
// longer knows the one it ran with.
//
// The desktop app drops its SDK clients when it locks — after 10 minutes of
// inactivity, or by hand. The SDK only recovers by itself from an error named
// DesktopSessionExpired; for a dropped client the app answers "invalid client
// id" instead, and every later call would fail the same way until the sidecar
// is restarted. Building the client anew asks the user to authorize again.
// All commands only read, so repeating one is harmless.
func withSession(call func() (any, error), reset func()) (any, error) {
	data, err := call()
	if err == nil || !strings.Contains(strings.ToLower(err.Error()), "invalid client id") {
		return data, err
	}
	fmt.Fprintf(os.Stderr, "op-sidecar: 1Password dropped the client (%v), authorizing again\n", err)
	reset()
	return call()
}

func (s *server) run(ctx context.Context, client *onepassword.Client, req request) (any, error) {
	switch req.Cmd {
	case "vaults":
		overviews, err := client.Vaults().List(ctx)
		if err != nil {
			return nil, err
		}
		out := make([]vault, 0, len(overviews))
		for _, v := range overviews {
			out = append(out, vault{ID: v.ID, Title: v.Title, ItemCount: v.ActiveItemCount})
		}
		return out, nil

	case "items":
		if req.Vault == "" {
			return nil, fmt.Errorf("items requires a vault id")
		}
		overviews, err := client.Items().List(ctx, req.Vault)
		if err != nil {
			return nil, err
		}
		out := make([]item, 0, len(overviews))
		for _, i := range overviews {
			out = append(out, item{ID: i.ID, Title: i.Title, Category: string(i.Category)})
		}
		return out, nil

	case "fields":
		if req.Vault == "" || req.Item == "" {
			return nil, fmt.Errorf("fields requires a vault and an item id")
		}
		it, err := client.Items().Get(ctx, req.Vault, req.Item)
		if err != nil {
			return nil, err
		}
		out := make([]field, 0, len(it.Fields))
		for _, f := range it.Fields {
			section := ""
			if f.SectionID != nil {
				section = *f.SectionID
			}
			out = append(out, field{
				ID:          f.ID,
				Title:       f.Title,
				SectionID:   section,
				FieldType:   string(f.FieldType),
				ValueLength: len(f.Value),
			})
		}
		return out, nil

	case "resolve":
		if req.Ref == "" {
			return nil, fmt.Errorf("resolve requires a secret reference")
		}
		return client.Secrets().Resolve(ctx, req.Ref)

	default:
		return nil, fmt.Errorf("unknown command %q", req.Cmd)
	}
}

// ensureClient builds the SDK client on first use. A failed attempt is not
// cached: the user may have had 1Password locked or declined the prompt, and
// the next request should try again.
func (s *server) ensureClient(ctx context.Context) (*onepassword.Client, error) {
	if s.client != nil {
		return s.client, nil
	}
	started := time.Now()
	if home, err := privateLibHome(); err == nil {
		// The SDK looks for the library under the user's home directory and
		// loads it once, here; afterwards the real home is back.
		real := os.Getenv("USERPROFILE")
		os.Setenv("USERPROFILE", home)
		defer os.Setenv("USERPROFILE", real)
	} else {
		fmt.Fprintf(os.Stderr, "op-sidecar: using 1Password's own library: %v\n", err)
	}
	client, err := onepassword.NewClient(ctx,
		onepassword.WithDesktopAppIntegration(s.account),
		onepassword.WithIntegrationInfo(integrationName, integrationVersion),
	)
	if err != nil {
		return nil, fmt.Errorf("1Password authentication failed: %w", err)
	}
	fmt.Fprintf(os.Stderr, "op-sidecar: client ready in %v\n", time.Since(started).Round(time.Millisecond))
	s.client = client
	return client, nil
}

// privateLibHome copies 1Password's SDK library into a directory of our own
// and returns a stand-in home directory under which the SDK finds that copy.
//
// Loaded in place, the library stays open for the life of the sidecar, and
// 1Password rewrites that file on every start. If it cannot because we hold
// it — an update while WireTerm runs — it does not start its SDK server at
// all, and every client fails with "file not found" until 1Password is
// restarted with WireTerm closed.
//
// The copy is named after the original's timestamp and size, so a newer
// library from an update gets a fresh copy on the next sidecar start.
func privateLibHome() (string, error) {
	if runtime.GOOS != "windows" {
		return "", fmt.Errorf("only needed on Windows")
	}
	local, err := os.UserCacheDir() // %LOCALAPPDATA%
	if err != nil {
		return "", err
	}
	src := filepath.Join(local, "1Password", "op_sdk_ipc_client.dll")
	info, err := os.Stat(src)
	if err != nil {
		return "", err
	}
	root := filepath.Join(local, "WireTerm", "op-sdk")
	stamp := fmt.Sprintf("%d-%d", info.ModTime().Unix(), info.Size())
	home := filepath.Join(root, stamp)
	dst := filepath.Join(home, "AppData", "Local", "1Password", "op_sdk_ipc_client.dll")

	if _, err := os.Stat(dst); err != nil {
		data, err := os.ReadFile(src)
		if err != nil {
			return "", err
		}
		if err := os.MkdirAll(filepath.Dir(dst), 0o755); err != nil {
			return "", err
		}
		// Written under another name first, so a sidecar stopped halfway
		// never leaves a truncated library that passes the Stat above.
		tmp := dst + ".tmp"
		if err := os.WriteFile(tmp, data, 0o644); err != nil {
			return "", err
		}
		if err := os.Rename(tmp, dst); err != nil {
			return "", err
		}
	}

	// Copies from before an update. One still loaded by another running
	// sidecar cannot be removed and is simply tried again next time.
	if entries, err := os.ReadDir(root); err == nil {
		for _, e := range entries {
			if e.Name() != stamp {
				os.RemoveAll(filepath.Join(root, e.Name()))
			}
		}
	}
	return home, nil
}

func (s *server) reply(r response) {
	if err := s.out.Encode(r); err != nil {
		fmt.Fprintf(os.Stderr, "op-sidecar: writing response: %v\n", err)
	}
}
