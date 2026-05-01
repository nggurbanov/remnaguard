package main

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"os"
	"os/signal"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/nggurbanov/remnaguard/internal/auth"
	"github.com/nggurbanov/remnaguard/internal/config"
	"github.com/nggurbanov/remnaguard/internal/policy"
	"github.com/nggurbanov/remnaguard/internal/routes"
	"github.com/nggurbanov/remnaguard/internal/server"
	"github.com/spf13/pflag"
	"gopkg.in/yaml.v3"
)

var (
	version = "dev"
	commit  = ""
)

func main() {
	if err := run(os.Args[1:]); err != nil {
		fmt.Fprintln(os.Stderr, "remnaguard:", err)
		os.Exit(1)
	}
}

func run(args []string) error {
	if len(args) == 0 {
		usage()
		return errors.New("missing command")
	}
	switch args[0] {
	case "serve":
		return serve(args[1:])
	case "validate":
		return validate(args[1:])
	case "routes":
		return routesCmd(args[1:])
	case "token":
		return tokenCmd(args[1:])
	case "policy":
		return policyCmd(args[1:])
	case "version", "--version", "-v":
		fmt.Println(version)
		return nil
	default:
		usage()
		return fmt.Errorf("unknown command %q", args[0])
	}
}

func usage() {
	fmt.Fprintln(os.Stderr, `usage:
  remnaguard serve -c remnaguard.yaml
  remnaguard validate -c remnaguard.yaml
  remnaguard routes list
  remnaguard routes check-openapi --spec remnawave-openapi.json
  remnaguard token generate [--id credential-id]
  remnaguard policy explain -c remnaguard.yaml --token token-id
  remnaguard policy test -c remnaguard.yaml --token token-id --method GET --path /api/users/{uuid}`)
}

func serve(args []string) error {
	fs := pflag.NewFlagSet("serve", pflag.ContinueOnError)
	cfgPath := fs.StringP("config", "c", "remnaguard.yaml", "config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	if cfg.Report.UnsafeReportProxy {
		fmt.Fprintln(os.Stderr, "warning: unsafe_report_proxy is enabled; would-deny policy failures may proxy upstream")
	}
	rt, err := server.NewRuntime(cfg, version, commit)
	if err != nil {
		return err
	}
	ctx, stop := signal.NotifyContext(context.Background(), os.Interrupt, syscall.SIGTERM)
	defer stop()
	sigHUP := make(chan os.Signal, 1)
	signal.Notify(sigHUP, syscall.SIGHUP)
	go func() {
		for range sigHUP {
			next, err := config.Load(*cfgPath)
			if err != nil {
				rt.Audit().Emit("reload_rejected", "", "", "", "invalid_config", 0)
				continue
			}
			if err := rt.Reload(next); err != nil {
				rt.Audit().Emit("reload_rejected", "", "", "", "invalid_config", 0)
				continue
			}
			rt.Audit().Emit("reload_applied", "", "", "", "ok", 0)
		}
	}()
	return rt.Serve(ctx)
}

func validate(args []string) error {
	fs := pflag.NewFlagSet("validate", pflag.ContinueOnError)
	cfgPath := fs.StringP("config", "c", "remnaguard.yaml", "config file")
	if err := fs.Parse(args); err != nil {
		return err
	}
	_, err := config.Load(*cfgPath)
	if err == nil {
		fmt.Println("config ok")
	}
	return err
}

func routesCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("missing routes subcommand")
	}
	switch args[0] {
	case "list":
		for _, route := range routes.Catalog("2.7.4") {
			fmt.Printf("%-7s %-48s %-20s %s\n", route.Method, route.Pattern, route.Support, strings.Join(route.Scopes, ","))
		}
		return nil
	case "check-openapi":
		fs := pflag.NewFlagSet("check-openapi", pflag.ContinueOnError)
		spec := fs.String("spec", "", "local OpenAPI JSON file")
		strict := fs.Bool("strict", false, "exit non-zero on drift")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		res, err := routes.CheckOpenAPI(*spec, routes.Catalog("2.7.4"))
		if err != nil {
			return err
		}
		if *strict {
			fmt.Printf("covered: %d\nunknown: %d\nremoved: %d\ncoverage: %.0f%%\n", len(res.Covered), len(res.Unknown), len(res.Removed), res.Coverage)
			if len(res.Invalid) > 0 || len(res.Ambiguous) > 0 || len(res.Duplicates) > 0 {
				fmt.Printf("invalid: %d\nambiguous: %d\nduplicates: %d\n", len(res.Invalid), len(res.Ambiguous), len(res.Duplicates))
			}
			if len(res.Unknown) > 0 || len(res.Removed) > 0 || len(res.Invalid) > 0 || len(res.Ambiguous) > 0 || len(res.Duplicates) > 0 {
				enc := json.NewEncoder(os.Stdout)
				enc.SetIndent("", "  ")
				_ = enc.Encode(res)
				return errors.New("route drift detected")
			}
			return nil
		}
		enc := json.NewEncoder(os.Stdout)
		enc.SetIndent("", "  ")
		_ = enc.Encode(res)
		return nil
	default:
		return fmt.Errorf("unknown routes subcommand %q", args[0])
	}
}

func tokenCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("missing token subcommand")
	}
	switch args[0] {
	case "generate":
		fs := pflag.NewFlagSet("generate", pflag.ContinueOnError)
		id := fs.String("id", "cred_"+randomID(8), "credential id")
		pepper := fs.String("pepper", "", "pepper for digest output")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		secret := make([]byte, 32)
		if _, err := rand.Read(secret); err != nil {
			return err
		}
		rawSecret := base64.RawURLEncoding.EncodeToString(secret)
		fmt.Printf("token: rg_%s.%s\n", *id, rawSecret)
		if *pepper != "" {
			fmt.Printf("hmac_sha256: %s\n", auth.Digest(rawSecret, []byte(*pepper)))
		}
		return nil
	case "add":
		fs := pflag.NewFlagSet("add", pflag.ContinueOnError)
		cfgPath := fs.StringP("config", "c", "remnaguard.yaml", "config file")
		tokenID := fs.String("id", "", "logical token id")
		credID := fs.String("credential", "cred_"+randomID(8), "credential id")
		scopes := fs.String("scopes", "users:read", "comma-separated scopes")
		outFile := fs.String("tokens-file", "", "token YAML file")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *tokenID == "" {
			return errors.New("--id is required")
		}
		secret, rawToken, digest, err := makeCredential(*credID)
		if err != nil {
			return err
		}
		_ = secret
		file := tokenFile(*cfgPath, *outFile, *tokenID)
		doc, err := readTokenFile(file)
		if err != nil {
			return err
		}
		if findTokenDoc(doc.Tokens, *tokenID) != nil {
			return fmt.Errorf("token %q already exists in %s", *tokenID, file)
		}
		doc.Tokens = append(doc.Tokens, config.TokenPolicy{ID: *tokenID, Scopes: splitCSV(*scopes), Credentials: []config.Credential{{ID: *credID, HMACSHA256: digest}}})
		if err := writeTokenFileWithValidation(file, doc, *cfgPath); err != nil {
			return err
		}
		fmt.Printf("token: %s\n", rawToken)
		return nil
	case "rotate":
		fs := pflag.NewFlagSet("rotate", pflag.ContinueOnError)
		cfgPath := fs.StringP("config", "c", "remnaguard.yaml", "config file")
		tokenID := fs.String("id", "", "logical token id")
		credID := fs.String("credential", "cred_"+randomID(8), "new credential id")
		file := fs.String("tokens-file", "", "token YAML file")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *tokenID == "" {
			return errors.New("--id is required")
		}
		doc, path, tok, err := loadTokenDocForEdit(*cfgPath, *file, *tokenID)
		if err != nil {
			return err
		}
		_, rawToken, digest, err := makeCredential(*credID)
		if err != nil {
			return err
		}
		tok.Credentials = append(tok.Credentials, config.Credential{ID: *credID, HMACSHA256: digest})
		if err := writeTokenFileWithValidation(path, doc, *cfgPath); err != nil {
			return err
		}
		fmt.Printf("token: %s\n", rawToken)
		return nil
	case "disable":
		fs := pflag.NewFlagSet("disable", pflag.ContinueOnError)
		cfgPath := fs.StringP("config", "c", "remnaguard.yaml", "config file")
		tokenID := fs.String("id", "", "logical token id")
		credID := fs.String("credential", "", "credential id")
		file := fs.String("tokens-file", "", "token YAML file")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *tokenID == "" || *credID == "" {
			return errors.New("--id and --credential are required")
		}
		doc, path, tok, err := loadTokenDocForEdit(*cfgPath, *file, *tokenID)
		if err != nil {
			return err
		}
		found := false
		for i := range tok.Credentials {
			if tok.Credentials[i].ID == *credID {
				tok.Credentials[i].Disabled = true
				found = true
			}
		}
		if !found {
			return fmt.Errorf("credential %q not found", *credID)
		}
		return writeTokenFileWithValidation(path, doc, *cfgPath)
	case "prune":
		fs := pflag.NewFlagSet("prune", pflag.ContinueOnError)
		cfgPath := fs.StringP("config", "c", "remnaguard.yaml", "config file")
		tokenID := fs.String("id", "", "logical token id")
		file := fs.String("tokens-file", "", "token YAML file")
		if err := fs.Parse(args[1:]); err != nil {
			return err
		}
		if *tokenID == "" {
			return errors.New("--id is required")
		}
		doc, path, tok, err := loadTokenDocForEdit(*cfgPath, *file, *tokenID)
		if err != nil {
			return err
		}
		kept := tok.Credentials[:0]
		for _, cred := range tok.Credentials {
			if !cred.Disabled {
				kept = append(kept, cred)
			}
		}
		tok.Credentials = kept
		return writeTokenFileWithValidation(path, doc, *cfgPath)
	default:
		return fmt.Errorf("unknown token subcommand %q", args[0])
	}
}

func policyCmd(args []string) error {
	if len(args) == 0 {
		return errors.New("missing policy subcommand")
	}
	fs := pflag.NewFlagSet(args[0], pflag.ContinueOnError)
	cfgPath := fs.StringP("config", "c", "remnaguard.yaml", "config file")
	tokenID := fs.String("token", "", "logical token id")
	method := fs.String("method", http.MethodGet, "method")
	path := fs.String("path", "/api/users/{uuid}", "path")
	if err := fs.Parse(args[1:]); err != nil {
		return err
	}
	cfg, err := config.Load(*cfgPath)
	if err != nil {
		return err
	}
	tok := cfg.FindToken(*tokenID)
	if tok == nil {
		return fmt.Errorf("token %q not found", *tokenID)
	}
	switch args[0] {
	case "explain":
		return json.NewEncoder(os.Stdout).Encode(tok)
	case "test":
		route, ok := routes.Match(routes.Catalog(cfg.Compatibility.EffectiveVersion()), *method, *path)
		if !ok {
			fmt.Println("deny: unknown route")
			return nil
		}
		dec := policy.Decide(tok, route)
		fmt.Println(dec.String())
		return nil
	default:
		return fmt.Errorf("unknown policy subcommand %q", args[0])
	}
}

func randomID(n int) string {
	b := make([]byte, n)
	_, _ = rand.Read(b)
	return base64.RawURLEncoding.EncodeToString(b)
}

type tokenDoc struct {
	Tokens []config.TokenPolicy `yaml:"tokens"`
}

func makeCredential(credID string) ([]byte, string, string, error) {
	pepper := os.Getenv("REMNAGUARD_TOKEN_PEPPER")
	if pepper == "" {
		return nil, "", "", errors.New("REMNAGUARD_TOKEN_PEPPER is required")
	}
	secret := make([]byte, 32)
	if _, err := rand.Read(secret); err != nil {
		return nil, "", "", err
	}
	rawSecret := base64.RawURLEncoding.EncodeToString(secret)
	return secret, "rg_" + credID + "." + rawSecret, auth.Digest(rawSecret, []byte(pepper)), nil
}

func tokenFile(cfgPath, explicit, tokenID string) string {
	if explicit != "" {
		return explicit
	}
	return filepath.Join(filepath.Dir(cfgPath), "tokens.d", tokenID+".yaml")
}

func readTokenFile(path string) (*tokenDoc, error) {
	var doc tokenDoc
	b, err := os.ReadFile(path)
	if errors.Is(err, os.ErrNotExist) {
		return &doc, nil
	}
	if err != nil {
		return nil, err
	}
	if err := yaml.Unmarshal(b, &doc); err != nil {
		return nil, err
	}
	return &doc, nil
}

func loadTokenDocForEdit(cfgPath, explicit, tokenID string) (*tokenDoc, string, *config.TokenPolicy, error) {
	candidates := []string{}
	if explicit != "" {
		candidates = append(candidates, explicit)
	} else {
		candidates = append(candidates, tokenFile(cfgPath, "", tokenID))
		matches, _ := filepath.Glob(filepath.Join(filepath.Dir(cfgPath), "tokens.d", "*.yaml"))
		candidates = append(candidates, matches...)
	}
	seen := map[string]bool{}
	for _, path := range candidates {
		if seen[path] {
			continue
		}
		seen[path] = true
		doc, err := readTokenFile(path)
		if err != nil {
			return nil, "", nil, err
		}
		if tok := findTokenDoc(doc.Tokens, tokenID); tok != nil {
			return doc, path, tok, nil
		}
	}
	return nil, "", nil, fmt.Errorf("token %q not found", tokenID)
}

func findTokenDoc(tokens []config.TokenPolicy, id string) *config.TokenPolicy {
	for i := range tokens {
		if tokens[i].ID == id {
			return &tokens[i]
		}
	}
	return nil
}

func writeTokenFileWithValidation(path string, doc *tokenDoc, cfgPath string) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	var backup string
	if _, err := os.Stat(path); err == nil {
		backup = fmt.Sprintf("%s.%s.bak", path, time.Now().UTC().Format("20060102T150405Z"))
		b, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		if err := os.WriteFile(backup, b, 0600); err != nil {
			return err
		}
	}
	b, err := yaml.Marshal(doc)
	if err != nil {
		return err
	}
	tmp, err := os.CreateTemp(filepath.Dir(path), ".remnaguard-*.tmp")
	if err != nil {
		return err
	}
	tmpName := tmp.Name()
	defer func() { _ = os.Remove(tmpName) }()
	if err := tmp.Chmod(0600); err != nil {
		_ = tmp.Close()
		return err
	}
	if _, err := tmp.Write(b); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Sync(); err != nil {
		_ = tmp.Close()
		return err
	}
	if err := tmp.Close(); err != nil {
		return err
	}
	if err := os.Rename(tmpName, path); err != nil {
		return err
	}
	if _, err := config.Load(cfgPath); err != nil {
		if backup != "" {
			_ = os.Rename(backup, path)
		}
		return fmt.Errorf("validation failed after token edit: %w", err)
	}
	return nil
}

func splitCSV(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part != "" {
			out = append(out, part)
		}
	}
	return out
}
