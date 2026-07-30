package migration

import (
	"bytes"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"syscall"
	"time"

	"gopkg.in/yaml.v3"
)

const (
	configVersion  = "dkim2-opendkim-migration-v1"
	maxConfigBytes = 256 << 10
)

// SourceConfig owns one verified read-only legacy LDAP authority.
type SourceConfig struct {
	Address      string `yaml:"address"`
	ServerName   string `yaml:"server_name"`
	CAFile       string `yaml:"ca_file"`
	Transport    string `yaml:"transport"`
	BindDN       string `yaml:"bind_dn"`
	PasswordFile string `yaml:"password_file"`
	BaseDN       string `yaml:"base_dn"`
	PageSize     uint16 `yaml:"page_size"`
}

// Limits bounds every inventory and report operation.
type Limits struct {
	Records       uint32 `yaml:"records"`
	ResponseBytes uint32 `yaml:"response_bytes"`
	ReportBytes   uint32 `yaml:"report_bytes"`
}

// PostgreSQLPublicationConfig owns one verified single-host SQL publisher.
type PostgreSQLPublicationConfig struct {
	Address      string `yaml:"address"`
	ServerName   string `yaml:"server_name"`
	CAFile       string `yaml:"ca_file"`
	Database     string `yaml:"database"`
	User         string `yaml:"user"`
	PasswordFile string `yaml:"password_file"`
}

// Config is one immutable-by-ownership offline migration configuration.
type Config struct {
	Version      string                       `yaml:"version"`
	Deadline     time.Duration                `yaml:"-"`
	DeadlineText string                       `yaml:"deadline"`
	Source       SourceConfig                 `yaml:"source"`
	Import       SourceConfig                 `yaml:"import"`
	LDAPPublish  *SourceConfig                `yaml:"ldap_publish,omitempty"`
	PGPublish    *PostgreSQLPublicationConfig `yaml:"postgresql_publish,omitempty"`
	Plan         Plan                         `yaml:"plan"`
	Limits       Limits                       `yaml:"limits"`
}

// LoadConfig reads one owner-only non-symlink configuration document.
func LoadConfig(path string) (Config, error) {
	if !filepath.IsAbs(path) || filepath.Clean(path) != path {
		return Config{}, errors.New("migration configuration unavailable")
	}
	document, err := readProtected(path, maxConfigBytes)
	if err != nil {
		return Config{}, errors.New("migration configuration unavailable")
	}
	defer clear(document)
	var config Config
	decoder := yaml.NewDecoder(bytes.NewReader(document))
	decoder.KnownFields(true)
	if err := decoder.Decode(&config); err != nil {
		return Config{}, errors.New("migration configuration unavailable")
	}
	var trailing any
	if decoder.Decode(&trailing) != io.EOF || config.validate(path) != nil {
		return Config{}, errors.New("migration configuration unavailable")
	}
	return config, nil
}

// validate enforces the complete closed migration configuration matrix.
//
//nolint:gocyclo // The offline authority matrix is intentionally closed and explicit.
func (c *Config) validate(configPath string) error {
	if c == nil || c.Version != configVersion ||
		(c.Plan.Target != TargetLDAP && c.Plan.Target != TargetPostgreSQL) ||
		!validSource(c.Source) || !validSource(c.Import) ||
		c.Source.BindDN == c.Import.BindDN ||
		c.Source.PasswordFile == c.Import.PasswordFile ||
		c.Limits.Records == 0 || c.Limits.Records > 4096 ||
		c.Limits.ResponseBytes == 0 || c.Limits.ResponseBytes > 32<<20 ||
		c.Limits.ReportBytes == 0 || c.Limits.ReportBytes > maxConfigBytes ||
		!filepath.IsAbs(c.Plan.RegistryRoot) ||
		filepath.Clean(c.Plan.RegistryRoot) != c.Plan.RegistryRoot ||
		len(c.Plan.Mappings) == 0 || len(c.Plan.Mappings) > int(c.Limits.Records) {
		return errors.New("migration configuration invalid")
	}
	if c.Plan.Target == TargetLDAP {
		if c.LDAPPublish == nil || c.PGPublish != nil ||
			!validSource(*c.LDAPPublish) ||
			c.LDAPPublish.BindDN == c.Source.BindDN ||
			c.LDAPPublish.BindDN == c.Import.BindDN ||
			c.LDAPPublish.PasswordFile == c.Source.PasswordFile ||
			c.LDAPPublish.PasswordFile == c.Import.PasswordFile {
			return errors.New("migration configuration invalid")
		}
	} else if c.LDAPPublish != nil || c.PGPublish == nil ||
		!validPostgreSQLPublication(*c.PGPublish) {
		return errors.New("migration configuration invalid")
	}
	deadline, err := time.ParseDuration(c.DeadlineText)
	if err != nil || deadline <= 0 || deadline > 30*time.Second {
		return errors.New("migration configuration invalid")
	}
	c.Deadline = deadline
	base := filepath.Dir(configPath)
	for _, path := range []string{
		c.Source.CAFile, c.Source.PasswordFile,
		c.Import.CAFile, c.Import.PasswordFile,
	} {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path ||
			filepath.Dir(path) != base || path == configPath {
			return errors.New("migration configuration invalid")
		}
	}
	publicationPaths := []string(nil)
	if c.LDAPPublish != nil {
		publicationPaths = []string{
			c.LDAPPublish.CAFile, c.LDAPPublish.PasswordFile,
		}
	} else if c.PGPublish != nil {
		publicationPaths = []string{
			c.PGPublish.CAFile, c.PGPublish.PasswordFile,
		}
	}
	for _, path := range publicationPaths {
		if !filepath.IsAbs(path) || filepath.Clean(path) != path ||
			filepath.Dir(path) != base || path == configPath {
			return errors.New("migration configuration invalid")
		}
	}
	return validatePlan(c.Plan)
}

// validSource validates one exact verified-TLS least-authority LDAP principal.
func validSource(source SourceConfig) bool {
	return validAuthority(source.Address, source.ServerName) &&
		(source.Transport == ldapTransportSecure || source.Transport == "starttls") &&
		source.BindDN != "" && source.BaseDN != "" &&
		source.PageSize > 0 && source.PageSize <= 256
}

// validPostgreSQLPublication validates one exact non-DSN SQL authority.
func validPostgreSQLPublication(config PostgreSQLPublicationConfig) bool {
	return validAuthority(config.Address, config.ServerName) &&
		config.Database != "" && len(config.Database) <= 128 &&
		config.User != "" && len(config.User) <= 128 &&
		config.CAFile != "" && config.PasswordFile != ""
}

// validatePlan rejects inferred, duplicate, or noncanonical DKIM2 mappings.
func validatePlan(plan Plan) error {
	generation, err := parseGeneration(plan.Generation)
	if err != nil {
		return err
	}
	current, err := parseExpectedCurrent(plan.ExpectedCurrent)
	if err != nil || generation <= current {
		return errors.New("migration plan invalid")
	}
	seenSource := make(map[string]struct{}, len(plan.Mappings))
	seenTarget := make(map[string]struct{}, len(plan.Mappings))
	seenHandle := make(map[string]struct{}, len(plan.Mappings))
	for _, mapping := range plan.Mappings {
		sourceSelector := mapping.legacySelector()
		if mapping.Domain == "" || mapping.Domain != strings.ToLower(mapping.Domain) ||
			sourceSelector == "" || sourceSelector != strings.ToLower(sourceSelector) ||
			mapping.Selector == "" || mapping.Selector != strings.ToLower(mapping.Selector) ||
			mapping.TenantID == "" || mapping.ProfileID == "" || mapping.HandleID == "" ||
			(mapping.ProfileUse != "originator" && mapping.ProfileUse != "ordinary_transit") ||
			mapping.Rollout != "enforce" || mapping.Compatibility != "strict" {
			return errors.New("migration plan invalid")
		}
		if _, _, valid := mapping.validity(); !valid {
			return errors.New("migration plan invalid")
		}
		sourceKey := mapping.Domain + "\x00" + sourceSelector
		if _, exists := seenSource[sourceKey]; exists {
			return errors.New("migration plan invalid")
		}
		targetKey := mapping.Domain + "\x00" + mapping.Selector
		if _, exists := seenTarget[targetKey]; exists {
			return errors.New("migration plan invalid")
		}
		if _, exists := seenHandle[mapping.HandleID]; exists {
			return errors.New("migration plan invalid")
		}
		seenSource[sourceKey] = struct{}{}
		seenTarget[targetKey] = struct{}{}
		seenHandle[mapping.HandleID] = struct{}{}
	}
	return nil
}

// parseGeneration preserves the full canonical uint64 range.
func parseGeneration(value string) (uint64, error) {
	generation, err := strconv.ParseUint(value, 10, 64)
	if err != nil || generation == 0 || strconv.FormatUint(generation, 10) != value {
		return 0, errors.New("migration generation invalid")
	}
	return generation, nil
}

// parseExpectedCurrent accepts canonical zero only as the explicit empty-backend fence.
func parseExpectedCurrent(value string) (uint64, error) {
	if value == "0" {
		return 0, nil
	}
	return parseGeneration(value)
}

// validAuthority accepts one direct IP endpoint and separate TLS identity.
func validAuthority(address, serverName string) bool {
	host, port, err := net.SplitHostPort(address)
	ip, parseErr := netip.ParseAddr(host)
	number, numberErr := strconv.ParseUint(port, 10, 16)
	return err == nil && parseErr == nil && numberErr == nil && number != 0 &&
		!ip.IsUnspecified() && !ip.IsMulticast() &&
		serverName != "" && len(serverName) <= 253
}

// readProtected reads one exact regular owner-only file without following links.
func readProtected(path string, maximum int64) ([]byte, error) {
	info, err := os.Lstat(path)
	if err != nil {
		return nil, errors.New("protected migration file unavailable")
	}
	stat, statOK := info.Sys().(*syscall.Stat_t)
	if !statOK || stat.Uid != uint32(os.Geteuid()) ||
		!info.Mode().IsRegular() || info.Mode().Perm() != 0o600 ||
		info.Size() <= 0 || info.Size() > maximum {
		return nil, errors.New("protected migration file unavailable")
	}
	file, err := os.OpenFile(path, os.O_RDONLY|syscall.O_NOFOLLOW, 0)
	if err != nil {
		return nil, errors.New("protected migration file unavailable")
	}
	defer func() { _ = file.Close() }()
	opened, err := file.Stat()
	if err != nil {
		return nil, errors.New("protected migration file unavailable")
	}
	openedStat, openedStatOK := opened.Sys().(*syscall.Stat_t)
	if !openedStatOK || openedStat.Uid != uint32(os.Geteuid()) ||
		!opened.Mode().IsRegular() || opened.Mode().Perm() != 0o600 ||
		opened.Size() <= 0 || opened.Size() > maximum ||
		openedStat.Nlink != 1 || openedStat.Dev != stat.Dev || openedStat.Ino != stat.Ino {
		return nil, errors.New("protected migration file unavailable")
	}
	document, err := io.ReadAll(io.LimitReader(file, maximum+1))
	if err != nil || int64(len(document)) > maximum {
		clear(document)
		return nil, errors.New("protected migration file unavailable")
	}
	return document, nil
}

// String returns a constant protected configuration summary.
func (Config) String() string { return redacted }

// GoString returns a constant protected configuration representation.
func (Config) GoString() string { return redacted }

// Format prevents formatting verbs from exposing migration configuration.
func (Config) Format(state fmt.State, _ rune) { _, _ = io.WriteString(state, redacted) }

// MarshalJSON rejects serialization of protected migration configuration.
func (Config) MarshalJSON() ([]byte, error) {
	return nil, errors.New("migration configuration serialization denied")
}
