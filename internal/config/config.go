package config

import (
	"errors"
	"fmt"
	"net"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"strings"
	"time"

	"github.com/nggurbanov/remnaguard/internal/ratelimit"
	"gopkg.in/yaml.v3"
)

type Config struct {
	Server        ServerConfig        `yaml:"server"`
	Upstream      UpstreamConfig      `yaml:"upstream"`
	Compatibility CompatibilityConfig `yaml:"compatibility"`
	Limits        LimitsConfig        `yaml:"limits"`
	Metrics       MetricsConfig       `yaml:"metrics"`
	Audit         AuditConfig         `yaml:"audit"`
	Alerts        AlertsConfig        `yaml:"alerts"`
	Report        ReportConfig        `yaml:"report"`
	PublicSubs    PublicSubsConfig    `yaml:"public_subscriptions"`
	PanelFacade   PanelFacadeConfig   `yaml:"panel_facade"`
	Reload        ReloadConfig        `yaml:"reload"`
	WriteSafety   WriteSafetyConfig   `yaml:"write_safety"`
	Tokens        []TokenPolicy       `yaml:"tokens"`
	Include       []string            `yaml:"include"`
	path          string
}

type ServerConfig struct {
	APIListen      string        `yaml:"api_listen"`
	LocalListen    string        `yaml:"local_listen"`
	ExposeLocal    bool          `yaml:"expose_local"`
	ReadTimeout    time.Duration `yaml:"read_timeout"`
	WriteTimeout   time.Duration `yaml:"write_timeout"`
	IdleTimeout    time.Duration `yaml:"idle_timeout"`
	HeaderTimeout  time.Duration `yaml:"read_header_timeout"`
	MaxHeaderBytes int           `yaml:"max_header_bytes"`
}

type UpstreamConfig struct {
	BaseURL               string            `yaml:"base_url"`
	BearerEnv             string            `yaml:"bearer_env"`
	BearerFile            string            `yaml:"bearer_file"`
	Bearer                string            `yaml:"bearer"`
	ExtraHeaders          map[string]string `yaml:"extra_headers"`
	AllowInsecureHTTP     bool              `yaml:"allow_insecure_http"`
	AllowInsecureTLS      bool              `yaml:"allow_insecure_tls"`
	CustomCAFile          string            `yaml:"custom_ca_file"`
	MTLSCertFile          string            `yaml:"mtls_cert_file"`
	MTLSKeyFile           string            `yaml:"mtls_key_file"`
	VersionPath           string            `yaml:"version_path"`
	ResponseHeaderTimeout time.Duration     `yaml:"response_header_timeout"`
}

type CompatibilityConfig struct {
	RemnawaveVersion     string `yaml:"remnawave_version"`
	AssumeVersion        string `yaml:"assume_version"`
	AllowVersionMismatch bool   `yaml:"allow_version_mismatch"`
}

type LimitsConfig struct {
	MaxPathLength       int           `yaml:"max_path_length"`
	MaxQueryLength      int           `yaml:"max_query_length"`
	MaxBodyBytes        int64         `yaml:"max_body_bytes"`
	GlobalConcurrency   int           `yaml:"global_concurrency"`
	PerTokenConcurrency int           `yaml:"per_token_concurrency"`
	DefaultRate         string        `yaml:"default_rate"`
	UpstreamBodyBytes   int64         `yaml:"upstream_body_bytes"`
	ShutdownGracePeriod time.Duration `yaml:"shutdown_grace_period"`
}

type MetricsConfig struct {
	Enabled bool `yaml:"enabled"`
}

type AuditConfig struct {
	Stdout     bool   `yaml:"stdout"`
	PepperEnv  string `yaml:"pepper_env"`
	SQLitePath string `yaml:"sqlite_path"`
}

type AlertsConfig struct {
	Enabled  bool                 `yaml:"enabled"`
	Telegram TelegramAlertsConfig `yaml:"telegram"`
}

type TelegramAlertsConfig struct {
	Enabled     bool          `yaml:"enabled"`
	BotTokenEnv string        `yaml:"bot_token_env"`
	ChatIDEnv   string        `yaml:"chat_id_env"`
	Cooldown    time.Duration `yaml:"cooldown"`
	QueueSize   int           `yaml:"queue_size"`
	Timeout     time.Duration `yaml:"timeout"`
	APIBaseURL  string        `yaml:"api_base_url"`
}

type ReportConfig struct {
	Enabled           bool `yaml:"enabled"`
	UnsafeReportProxy bool `yaml:"unsafe_report_proxy"`
}

type PublicSubsConfig struct {
	Enabled                 bool              `yaml:"enabled"`
	ShortUUIDRegex          string            `yaml:"short_uuid_regex"`
	AllowedClients          []string          `yaml:"allowed_client_types"`
	RequestHeaderAllowlist  []string          `yaml:"request_header_allowlist"`
	ResponseHeaderAllowlist []string          `yaml:"response_header_allowlist"`
	ExtraHeaders            map[string]string `yaml:"extra_headers"`
	ExtraResponseHeaders    map[string]string `yaml:"extra_response_headers"`
	AuthHeaderName          string            `yaml:"auth_header_name"`
	AuthHeaderEnv           string            `yaml:"auth_header_env"`
	PerIPConcurrency        int               `yaml:"per_ip_concurrency"`
	PerIPRate               string            `yaml:"per_ip_rate"`
}

type PanelFacadeConfig struct {
	Enabled  bool                      `yaml:"enabled"`
	Session  PanelFacadeSessionConfig  `yaml:"session"`
	Telegram PanelFacadeTelegramConfig `yaml:"telegram"`
	Actors   PanelFacadeActorsConfig   `yaml:"actors"`
}

type PanelFacadeSessionConfig struct {
	Issuer    string        `yaml:"issuer"`
	Audience  string        `yaml:"audience"`
	TokenTTL  time.Duration `yaml:"token_ttl"`
	SecretEnv string        `yaml:"secret_env"`
}

type PanelFacadeTelegramConfig struct {
	BotTokenEnv string        `yaml:"bot_token_env"`
	AuthMaxAge  time.Duration `yaml:"auth_max_age"`
}

type PanelFacadeActorsConfig struct {
	Telegram map[string]PanelFacadeTelegramActor `yaml:"telegram"`
}

type PanelFacadeTelegramActor struct {
	CredentialID string `yaml:"credential_id"`
	DisplayName  string `yaml:"display_name"`
}

type ReloadConfig struct {
	SIGHUP                       bool `yaml:"sighup"`
	WatchFiles                   bool `yaml:"watch_files"`
	AllowInsecureSecretFilePerms bool `yaml:"allow_insecure_secret_file_permissions"`
}

type WriteSafetyConfig struct {
	SingleWriter             bool `yaml:"single_writer"`
	EnableRestrictedWrites   bool `yaml:"enable_restricted_writes"`
	EnableTenantWritesLegacy bool `yaml:"enable_tenant_writes"`
}

type TokenPolicy struct {
	ID          string       `yaml:"id" json:"id"`
	Credentials []Credential `yaml:"credentials" json:"credentials"`
	Scopes      []string     `yaml:"scopes" json:"scopes"`
	Disabled    bool         `yaml:"disabled" json:"disabled"`
	Constraints Constraints  `yaml:"constraints" json:"constraints"`
}

type Credential struct {
	ID         string `yaml:"id" json:"id"`
	HMACSHA256 string `yaml:"hmac_sha256" json:"hmac_sha256"`
	Disabled   bool   `yaml:"disabled" json:"disabled"`
}

type Constraints struct {
	UsernamePrefix                 string              `yaml:"username_prefix" json:"username_prefix"`
	UsernameSuffix                 string              `yaml:"username_suffix" json:"username_suffix"`
	UsernameContains               string              `yaml:"username_contains" json:"username_contains"`
	UsernameRegex                  string              `yaml:"username_regex" json:"username_regex"`
	EmailContains                  string              `yaml:"email_contains" json:"email_contains"`
	EmailDomains                   []string            `yaml:"email_domains" json:"email_domains"`
	TelegramIDRanges               []IDRange           `yaml:"telegram_id_ranges" json:"telegram_id_ranges"`
	AllowedInternalSquads          []string            `yaml:"allowed_internal_squads" json:"allowed_internal_squads"`
	AllowedExternalSquads          []string            `yaml:"allowed_external_squads" json:"allowed_external_squads"`
	AllowedSubscriptionPageConfigs []string            `yaml:"allowed_subscription_page_configs" json:"allowed_subscription_page_configs"`
	MaxTrafficLimitBytes           int64               `yaml:"max_traffic_limit_bytes" json:"max_traffic_limit_bytes"`
	ForbidUnlimitedTraffic         bool                `yaml:"forbid_unlimited_traffic" json:"forbid_unlimited_traffic"`
	MaxDescriptionLength           int                 `yaml:"max_description_length" json:"max_description_length"`
	AllowedRequestFields           map[string][]string `yaml:"allowed_request_fields" json:"allowed_request_fields"`
}

type IDRange struct {
	Min int64 `yaml:"min" json:"min"`
	Max int64 `yaml:"max" json:"max"`
}

func Load(path string) (*Config, error) {
	cfg := Defaults()
	if err := loadInto(path, cfg); err != nil {
		return nil, err
	}
	base := filepath.Dir(path)
	for _, inc := range cfg.Include {
		matches, err := filepath.Glob(filepath.Join(base, inc))
		if err != nil {
			return nil, err
		}
		for _, match := range matches {
			var child Config
			if err := loadInto(match, &child); err != nil {
				return nil, err
			}
			cfg.Tokens = append(cfg.Tokens, child.Tokens...)
		}
	}
	cfg.path = path
	if err := cfg.Validate(); err != nil {
		return nil, err
	}
	return cfg, nil
}

func Defaults() *Config {
	return &Config{
		Server:        ServerConfig{APIListen: ":8080", LocalListen: "127.0.0.1:8081", ReadTimeout: 15 * time.Second, WriteTimeout: 60 * time.Second, IdleTimeout: 60 * time.Second, HeaderTimeout: 5 * time.Second, MaxHeaderBytes: 1 << 20},
		Compatibility: CompatibilityConfig{RemnawaveVersion: "2.7.4"},
		Limits:        LimitsConfig{MaxPathLength: 2048, MaxQueryLength: 4096, MaxBodyBytes: 1 << 20, GlobalConcurrency: 128, PerTokenConcurrency: 8, DefaultRate: "600/m", UpstreamBodyBytes: 64 << 20, ShutdownGracePeriod: 10 * time.Second},
		Audit:         AuditConfig{Stdout: true, PepperEnv: "REMNAGUARD_AUDIT_PEPPER"},
		Alerts:        AlertsConfig{Telegram: TelegramAlertsConfig{Cooldown: 5 * time.Minute, QueueSize: 100, Timeout: 5 * time.Second, APIBaseURL: "https://api.telegram.org"}},
		PublicSubs:    PublicSubsConfig{ShortUUIDRegex: `^[A-Za-z0-9_-]{6,64}$`, AllowedClients: []string{"sing-box", "clash", "v2ray", "hiddify"}, RequestHeaderAllowlist: []string{"user-agent", "accept", "x-hwid", "x-device-os", "x-ver-os", "x-device-model", "x-app-version"}, ResponseHeaderAllowlist: []string{"content-type", "content-disposition", "subscription-userinfo", "profile-update-interval", "profile-web-page-url", "support-url", "x-provider-id"}, PerIPConcurrency: 8, PerIPRate: "120/m"},
	}
}

func loadInto(path string, cfg *Config) error {
	b, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	if err := yaml.Unmarshal(b, cfg); err != nil {
		return err
	}
	return nil
}

func (c *Config) Validate() error {
	if c.Upstream.BaseURL == "" {
		return errors.New("upstream.base_url is required")
	}
	u, err := url.Parse(c.Upstream.BaseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errors.New("upstream.base_url must be absolute")
	}
	if u.Scheme != "https" && !c.Upstream.AllowInsecureHTTP && !isLocalHost(u.Hostname()) {
		return errors.New("upstream must be https unless localhost/private insecure override is explicit")
	}
	if c.configuredBearerSources() != 1 {
		return errors.New("exactly one upstream bearer source must be configured")
	}
	if err := c.validateAlerts(); err != nil {
		return err
	}
	if err := c.validatePanelFacade(); err != nil {
		return err
	}
	if c.resolveBearer() == "" {
		return errors.New("configured upstream bearer source must resolve to a non-empty value")
	}
	if c.Limits.MaxPathLength <= 0 {
		return errors.New("limits.max_path_length must be positive")
	}
	if c.Limits.MaxQueryLength <= 0 {
		return errors.New("limits.max_query_length must be positive")
	}
	if c.Limits.MaxBodyBytes <= 0 {
		return errors.New("limits.max_body_bytes must be positive")
	}
	if c.Limits.UpstreamBodyBytes <= 0 {
		return errors.New("limits.upstream_body_bytes must be positive")
	}
	if c.Limits.GlobalConcurrency <= 0 {
		return errors.New("limits.global_concurrency must be positive")
	}
	if c.Limits.PerTokenConcurrency <= 0 {
		return errors.New("limits.per_token_concurrency must be positive")
	}
	if c.PublicSubs.PerIPConcurrency <= 0 {
		return errors.New("public_subscriptions.per_ip_concurrency must be positive")
	}
	if _, err := ratelimit.NewFixedWindow(c.Limits.DefaultRate); err != nil {
		return err
	}
	if _, err := ratelimit.NewFixedWindow(c.PublicSubs.PerIPRate); err != nil {
		return err
	}
	if c.Upstream.BearerFile != "" && !c.Reload.AllowInsecureSecretFilePerms {
		if err := secureFile(c.Upstream.BearerFile); err != nil {
			return err
		}
	}
	if c.Upstream.MTLSCertFile != "" || c.Upstream.MTLSKeyFile != "" {
		if c.Upstream.MTLSCertFile == "" || c.Upstream.MTLSKeyFile == "" {
			return errors.New("both upstream.mtls_cert_file and upstream.mtls_key_file are required for mTLS")
		}
	}
	if c.Compatibility.EffectiveVersion() == "" {
		return errors.New("compatibility.remnawave_version or assume_version is required")
	}
	if c.Compatibility.EffectiveVersion() != "2.7.4" {
		return fmt.Errorf("unsupported Remnawave version %q", c.Compatibility.EffectiveVersion())
	}
	if _, err := regexp.Compile(c.PublicSubs.ShortUUIDRegex); err != nil {
		return fmt.Errorf("invalid public_subscriptions.short_uuid_regex: %w", err)
	}
	if c.PublicSubs.AuthHeaderName != "" && protectedOutboundHeader(c.PublicSubs.AuthHeaderName) {
		return fmt.Errorf("invalid public subscription auth header %q", c.PublicSubs.AuthHeaderName)
	}
	if c.PublicSubs.AuthHeaderName != "" && c.PublicSubs.AuthHeaderEnv == "" {
		return errors.New("public subscription auth_header_env is required when auth_header_name is set")
	}
	if c.PublicSubs.AuthHeaderName != "" && strings.TrimSpace(os.Getenv(c.PublicSubs.AuthHeaderEnv)) == "" {
		return errors.New("public subscription auth_header_env must resolve to a non-empty value")
	}
	for _, name := range c.PublicSubs.RequestHeaderAllowlist {
		if protectedOutboundHeader(name) {
			return fmt.Errorf("protected or invalid public subscription request header %q", name)
		}
	}
	for _, name := range c.PublicSubs.ResponseHeaderAllowlist {
		if !validHeaderName(name) {
			return fmt.Errorf("invalid public subscription header %q", name)
		}
	}
	for name := range c.PublicSubs.ExtraResponseHeaders {
		if protectedResponseHeader(name) {
			return fmt.Errorf("invalid public subscription extra response header %q", name)
		}
	}
	for name := range c.PublicSubs.ExtraHeaders {
		if protectedOutboundHeader(name) {
			return fmt.Errorf("protected or invalid public subscription extra header %q", name)
		}
	}
	for _, client := range c.PublicSubs.AllowedClients {
		if client == "" || strings.Contains(client, "/") {
			return fmt.Errorf("invalid public subscription client type %q", client)
		}
	}
	if c.Server.LocalListen == "" {
		return errors.New("server.local_listen is required")
	}
	if c.Server.ExposeLocal && strings.HasPrefix(c.Server.LocalListen, "127.0.0.1:") {
		return errors.New("server.expose_local cannot be true while local listener is localhost-only")
	}
	if os.Getenv("REMNAGUARD_TOKEN_PEPPER") == "" && len(c.Tokens) > 0 {
		return errors.New("REMNAGUARD_TOKEN_PEPPER is required when tokens are configured")
	}
	credIDs := map[string]bool{}
	tokenIDs := map[string]bool{}
	for _, tok := range c.Tokens {
		if tok.ID == "" {
			return errors.New("token id is required")
		}
		if tokenIDs[tok.ID] {
			return fmt.Errorf("duplicate token id %q", tok.ID)
		}
		tokenIDs[tok.ID] = true
		for _, scope := range tok.Scopes {
			if !KnownScope(scope) {
				return fmt.Errorf("unknown scope %q on token %q", scope, tok.ID)
			}
		}
		if tok.Constraints.UsernameRegex != "" {
			if _, err := regexp.Compile(tok.Constraints.UsernameRegex); err != nil {
				return fmt.Errorf("invalid username_regex on token %q: %w", tok.ID, err)
			}
		}
		for _, r := range tok.Constraints.TelegramIDRanges {
			if r.Min < 0 || r.Max < r.Min {
				return fmt.Errorf("invalid telegram_id_ranges on token %q", tok.ID)
			}
		}
		for routeName, fields := range tok.Constraints.AllowedRequestFields {
			if strings.TrimSpace(routeName) == "" {
				return fmt.Errorf("empty allowed_request_fields route on token %q", tok.ID)
			}
			if len(fields) == 0 {
				return fmt.Errorf("empty allowed_request_fields for route %q on token %q", routeName, tok.ID)
			}
			for _, field := range fields {
				if strings.TrimSpace(field) == "" {
					return fmt.Errorf("empty allowed request field for route %q on token %q", routeName, tok.ID)
				}
			}
		}
		for _, cred := range tok.Credentials {
			if cred.ID == "" || cred.HMACSHA256 == "" {
				return fmt.Errorf("credential id and hmac_sha256 are required on token %q", tok.ID)
			}
			if credIDs[cred.ID] {
				return fmt.Errorf("duplicate credential id %q", cred.ID)
			}
			credIDs[cred.ID] = true
		}
	}
	for name := range c.Upstream.ExtraHeaders {
		if protectedOutboundHeader(name) {
			return fmt.Errorf("protected or invalid upstream extra header %q", name)
		}
	}
	return nil
}

func (c *Config) validatePanelFacade() error {
	panel := c.PanelFacade
	if !panel.Enabled {
		return nil
	}
	if strings.TrimSpace(panel.Session.Issuer) == "" {
		return errors.New("panel_facade.session.issuer is required")
	}
	if strings.TrimSpace(panel.Session.Audience) == "" {
		return errors.New("panel_facade.session.audience is required")
	}
	if panel.Session.TokenTTL <= 0 {
		return errors.New("panel_facade.session.token_ttl must be positive")
	}
	if strings.TrimSpace(panel.Session.SecretEnv) == "" {
		return errors.New("panel_facade.session.secret_env is required")
	}
	if strings.TrimSpace(os.Getenv(panel.Session.SecretEnv)) == "" {
		return errors.New("panel_facade.session.secret_env must resolve to a non-empty value")
	}
	if strings.TrimSpace(panel.Telegram.BotTokenEnv) == "" {
		return errors.New("panel_facade.telegram.bot_token_env is required")
	}
	if strings.TrimSpace(os.Getenv(panel.Telegram.BotTokenEnv)) == "" {
		return errors.New("panel_facade.telegram.bot_token_env must resolve to a non-empty value")
	}
	if panel.Telegram.AuthMaxAge <= 0 {
		return errors.New("panel_facade.telegram.auth_max_age must be positive")
	}
	if len(panel.Actors.Telegram) == 0 {
		return errors.New("panel_facade.actors.telegram must contain at least one actor")
	}
	for telegramID, actor := range panel.Actors.Telegram {
		if strings.TrimSpace(telegramID) == "" {
			return errors.New("panel_facade.actors.telegram contains an empty telegram id")
		}
		credentialID := strings.TrimSpace(actor.CredentialID)
		if credentialID == "" {
			return fmt.Errorf("panel_facade actor %q credential_id is required", telegramID)
		}
		if strings.HasPrefix(credentialID, "rg_") {
			return fmt.Errorf("panel_facade actor %q credential_id must reference a stored credential id, not a raw token", telegramID)
		}
		if _, cred := c.FindCredential(credentialID); cred == nil {
			return fmt.Errorf("panel_facade actor %q references missing or disabled credential %q", telegramID, credentialID)
		}
	}
	return nil
}

func (c *Config) validateAlerts() error {
	tg := c.Alerts.Telegram
	if !c.Alerts.Enabled {
		return nil
	}
	if !tg.Enabled {
		return errors.New("alerts.telegram.enabled is required when alerts.enabled is true")
	}
	if strings.TrimSpace(tg.BotTokenEnv) == "" {
		return errors.New("alerts.telegram.bot_token_env is required")
	}
	if strings.TrimSpace(tg.ChatIDEnv) == "" {
		return errors.New("alerts.telegram.chat_id_env is required")
	}
	if strings.TrimSpace(os.Getenv(tg.BotTokenEnv)) == "" {
		return errors.New("alerts.telegram.bot_token_env must resolve to a non-empty value")
	}
	if strings.TrimSpace(os.Getenv(tg.ChatIDEnv)) == "" {
		return errors.New("alerts.telegram.chat_id_env must resolve to a non-empty value")
	}
	if tg.Cooldown <= 0 {
		return errors.New("alerts.telegram.cooldown must be positive")
	}
	if tg.QueueSize < 0 {
		return errors.New("alerts.telegram.queue_size must not be negative")
	}
	if tg.Timeout <= 0 {
		return errors.New("alerts.telegram.timeout must be positive")
	}
	baseURL := strings.TrimSpace(tg.APIBaseURL)
	if baseURL == "" {
		return errors.New("alerts.telegram.api_base_url is required")
	}
	u, err := url.Parse(baseURL)
	if err != nil || u.Scheme == "" || u.Host == "" {
		return errors.New("alerts.telegram.api_base_url must be absolute")
	}
	if u.Scheme != "https" && !isLocalHost(u.Hostname()) {
		return errors.New("alerts.telegram.api_base_url must be https unless localhost")
	}
	return nil
}

func (c *Config) ResolveBearer() string { return c.resolveBearer() }

func (c *Config) configuredBearerSources() int {
	count := 0
	if c.Upstream.Bearer != "" {
		count++
	}
	if c.Upstream.BearerEnv != "" {
		count++
	}
	if c.Upstream.BearerFile != "" {
		count++
	}
	return count
}

func (c *Config) resolveBearer() string {
	count := 0
	val := ""
	if c.Upstream.Bearer != "" {
		count++
		val = c.Upstream.Bearer
	}
	if c.Upstream.BearerEnv != "" && os.Getenv(c.Upstream.BearerEnv) != "" {
		count++
		val = os.Getenv(c.Upstream.BearerEnv)
	}
	if c.Upstream.BearerFile != "" {
		b, err := os.ReadFile(c.Upstream.BearerFile)
		if err == nil && strings.TrimSpace(string(b)) != "" {
			count++
			val = strings.TrimSpace(string(b))
		}
	}
	if count != 1 {
		return ""
	}
	return val
}

func (c CompatibilityConfig) EffectiveVersion() string {
	if c.AssumeVersion != "" {
		return c.AssumeVersion
	}
	return c.RemnawaveVersion
}

func (c *Config) FindCredential(id string) (*TokenPolicy, *Credential) {
	for i := range c.Tokens {
		if c.Tokens[i].Disabled {
			continue
		}
		for j := range c.Tokens[i].Credentials {
			if c.Tokens[i].Credentials[j].ID == id && !c.Tokens[i].Credentials[j].Disabled {
				return &c.Tokens[i], &c.Tokens[i].Credentials[j]
			}
		}
	}
	return nil, nil
}

func (c *Config) FindToken(id string) *TokenPolicy {
	for i := range c.Tokens {
		if c.Tokens[i].ID == id {
			return &c.Tokens[i]
		}
	}
	return nil
}

func KnownScope(scope string) bool {
	switch scope {
	case "users:read", "users:create", "users:update", "users:action", "user:read", "user:write", "user:action", "hwid:read", "hwid:write", "squads:read", "squad:read", "system:read", "metadata:read", "subscriptions:read", "subscription:read", "subscription-pages:read", "subscription-pages:write", "remnawave:*", "privileged:*":
		return true
	default:
		return false
	}
}

func (c WriteSafetyConfig) RestrictedWritesEnabled() bool {
	return c.EnableRestrictedWrites || c.EnableTenantWritesLegacy
}

func isLocalHost(host string) bool {
	if host == "localhost" {
		return true
	}
	ip := net.ParseIP(host)
	return ip != nil && (ip.IsLoopback() || ip.IsPrivate())
}

func validHeaderName(name string) bool {
	return http.CanonicalHeaderKey(name) != "" && !strings.ContainsAny(name, " \t\r\n:")
}

func protectedOutboundHeader(name string) bool {
	if !validHeaderName(name) {
		return true
	}
	lower := strings.ToLower(name)
	if strings.HasPrefix(lower, "x-forwarded-") || strings.HasPrefix(lower, "proxy-") {
		return true
	}
	switch lower {
	case "authorization", "cookie", "set-cookie", "host", "forwarded", "x-real-ip", "connection", "keep-alive", "te", "trailer", "transfer-encoding", "upgrade", "content-length", "accept-encoding", "content-encoding":
		return true
	default:
		return false
	}
}

func protectedResponseHeader(name string) bool {
	if protectedOutboundHeader(name) {
		return true
	}
	switch strings.ToLower(name) {
	case "location":
		return true
	default:
		return false
	}
}

func secureFile(path string) error {
	st, err := os.Stat(path)
	if err != nil {
		return err
	}
	if st.Mode().Perm()&0077 != 0 {
		return fmt.Errorf("secret file %s has insecure permissions %o", path, st.Mode().Perm())
	}
	return nil
}
