package migration

import (
	"bytes"
	"context"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"net"

	"github.com/croessner/dkim2"
)

// RunDryRunFile executes the complete offline protected inventory path.
func RunDryRunFile(
	ctx context.Context,
	path string,
	machine bool,
	toolVersion string,
) ([]byte, error) {
	config, err := LoadConfig(path)
	if err != nil {
		return nil, errors.New("migration dry run failed")
	}
	password, err := readProtected(config.Source.PasswordFile, 16<<10)
	if err != nil {
		return nil, errors.New("migration dry run failed")
	}
	defer clear(password)
	caDocument, err := readProtected(config.Source.CAFile, 1<<20)
	if err != nil {
		return nil, errors.New("migration dry run failed")
	}
	defer clear(caDocument)
	roots, err := parseRoots(caDocument)
	if err != nil {
		return nil, errors.New("migration dry run failed")
	}
	for index := range roots {
		defer clear(roots[index])
	}
	runCtx, cancel := context.WithTimeout(ctx, config.Deadline)
	defer cancel()
	client, closeClient, err := NewLDAPInventoryClient(
		runCtx, config.Source, password, roots,
	)
	if err != nil {
		return nil, errors.New("migration dry run failed")
	}
	defer func() { _ = closeClient() }()
	report, err := DryRun(runCtx, config, client, toolVersion)
	if err != nil {
		return nil, errors.New("migration dry run failed")
	}
	if machine {
		return EncodeMachineReport(report, config.Limits.ReportBytes)
	}
	return EncodeHumanReport(report, config.Limits.ReportBytes)
}

// RunApplyFile executes one complete offline protected publication.
func RunApplyFile(
	ctx context.Context,
	path string,
	machine bool,
	toolVersion string,
) ([]byte, error) {
	return runMutationFile(ctx, path, "", machine, toolVersion, false)
}

// RunRollbackFile republishes prior logical content under the configured higher generation.
func RunRollbackFile(
	ctx context.Context,
	path string,
	generation string,
	machine bool,
	toolVersion string,
) ([]byte, error) {
	return runMutationFile(ctx, path, generation, machine, toolVersion, true)
}

// runMutationFile owns every least-authority migration phase and cleanup.
func runMutationFile(
	ctx context.Context,
	path string,
	generation string,
	machine bool,
	toolVersion string,
	rollback bool,
) ([]byte, error) {
	config, err := LoadConfig(path)
	if err != nil || ctx == nil {
		return nil, errors.New("migration publication failed")
	}
	if rollback {
		parsed, parseErr := parseGeneration(generation)
		configured, configuredErr := parseGeneration(config.Plan.Generation)
		if parseErr != nil || configuredErr != nil || parsed != configured {
			return nil, errors.New("migration publication failed")
		}
	} else if generation != "" {
		return nil, errors.New("migration publication failed")
	}
	runCtx, cancel := context.WithTimeout(ctx, config.Deadline)
	defer cancel()
	inventoryPassword, inventoryRoots, err := loadPrincipal(config.Source)
	if err != nil {
		return nil, errors.New("migration publication failed")
	}
	defer clearPrincipal(inventoryPassword, inventoryRoots)
	inventoryClient, closeInventory, err := NewLDAPInventoryClient(
		runCtx, config.Source, inventoryPassword, inventoryRoots,
	)
	if err != nil {
		return nil, errors.New("migration publication failed")
	}
	defer func() { _ = closeInventory() }()
	records, counts, err := Inventory(runCtx, inventoryClient, config.Limits)
	if err != nil || ValidatePlan(records, config.Plan, &counts) != nil {
		return nil, errors.New("migration publication failed")
	}
	importPassword, importRoots, err := loadPrincipal(config.Import)
	if err != nil {
		return nil, errors.New("migration publication failed")
	}
	defer clearPrincipal(importPassword, importRoots)
	importClient, closeImport, err := NewLDAPKeyImportClient(
		runCtx, config.Import, importPassword, importRoots,
	)
	if err != nil {
		return nil, errors.New("migration publication failed")
	}
	defer func() { _ = closeImport() }()
	transport, err := dkim2.NewNetTXTTransport(net.DefaultResolver)
	if err != nil {
		return nil, errors.New("migration publication failed")
	}
	prover, err := NewFreshDNSProver(transport)
	if err != nil {
		return nil, errors.New("migration publication failed")
	}
	imported, err := ImportKeys(runCtx, records, config.Plan, importClient, prover)
	if err != nil {
		return nil, errors.New("migration publication failed")
	}
	defer closeImported(imported)
	publisher, closePublisher, err := openPublisher(runCtx, config)
	if err != nil {
		return nil, errors.New("migration publication failed")
	}
	defer func() { _ = closePublisher() }()
	var report Report
	if rollback {
		report, err = Rollback(
			runCtx, records, config.Plan, imported, publisher, toolVersion,
		)
	} else {
		report, err = Apply(
			runCtx, records, config.Plan, imported, publisher, toolVersion,
		)
	}
	if err != nil {
		return nil, errors.New("migration publication failed")
	}
	if machine {
		return EncodeMachineReport(report, config.Limits.ReportBytes)
	}
	return EncodeHumanReport(report, config.Limits.ReportBytes)
}

// openPublisher opens only the configured target publication authority.
func openPublisher(
	ctx context.Context,
	config Config,
) (Publisher, func() error, error) {
	if config.Plan.Target == TargetLDAP && config.LDAPPublish != nil {
		password, roots, err := loadPrincipal(*config.LDAPPublish)
		if err != nil {
			return nil, nil, errors.New("migration publication failed")
		}
		publisher, closePublisher, err := NewLDAPPublisherClient(
			ctx, *config.LDAPPublish, password, roots,
		)
		clearPrincipal(password, roots)
		if err != nil {
			return nil, nil, errors.New("migration publication failed")
		}
		return publisher, closePublisher, nil
	}
	if config.Plan.Target == TargetPostgreSQL && config.PGPublish != nil {
		password, roots, err := loadSQLPrincipal(*config.PGPublish)
		if err != nil {
			return nil, nil, errors.New("migration publication failed")
		}
		publisher, closePublisher, err := NewPostgreSQLPublisherClient(
			ctx, *config.PGPublish, password, roots,
		)
		clearPrincipal(password, roots)
		if err != nil {
			return nil, nil, errors.New("migration publication failed")
		}
		return publisher, closePublisher, nil
	}
	if config.Plan.Target == TargetMySQL && config.MySQLPublish != nil {
		password, roots, err := loadSQLPrincipal(*config.MySQLPublish)
		if err != nil {
			return nil, nil, errors.New("migration publication failed")
		}
		publisher, closePublisher, err := NewMySQLPublisherClient(
			ctx, *config.MySQLPublish, password, roots,
		)
		clearPrincipal(password, roots)
		if err != nil {
			return nil, nil, errors.New("migration publication failed")
		}
		return publisher, closePublisher, nil
	}
	return nil, nil, errors.New("migration publication failed")
}

// loadPrincipal reads one LDAP principal password and strict CA bundle.
func loadPrincipal(source SourceConfig) ([]byte, [][]byte, error) {
	return loadProtectedPrincipal(source.PasswordFile, source.CAFile)
}

// loadSQLPrincipal reads one SQL principal password and strict CA bundle.
func loadSQLPrincipal(
	source SQLPublicationConfig,
) ([]byte, [][]byte, error) {
	return loadProtectedPrincipal(source.PasswordFile, source.CAFile)
}

// loadProtectedPrincipal owns protected password and trust loading.
func loadProtectedPrincipal(
	passwordPath string,
	caPath string,
) ([]byte, [][]byte, error) {
	password, err := readProtected(passwordPath, 16<<10)
	if err != nil {
		return nil, nil, errors.New("migration principal unavailable")
	}
	caDocument, err := readProtected(caPath, 1<<20)
	if err != nil {
		clear(password)
		return nil, nil, errors.New("migration principal unavailable")
	}
	roots, err := parseRoots(caDocument)
	clear(caDocument)
	if err != nil {
		clear(password)
		return nil, nil, errors.New("migration principal unavailable")
	}
	return password, roots, nil
}

// clearPrincipal clears detached password and CA bytes.
func clearPrincipal(password []byte, roots [][]byte) {
	clear(password)
	for index := range roots {
		clear(roots[index])
	}
}

// parseRoots validates one strict CA-only PEM bundle.
func parseRoots(document []byte) ([][]byte, error) {
	remaining := document
	var roots [][]byte
	for len(bytes.TrimSpace(remaining)) != 0 {
		block, rest := pem.Decode(remaining)
		if block == nil || block.Type != "CERTIFICATE" || len(block.Headers) != 0 ||
			len(block.Bytes) == 0 || len(block.Bytes) > 64<<10 {
			return nil, errors.New("migration trust unavailable")
		}
		certificate, err := x509.ParseCertificate(block.Bytes)
		if err != nil || !certificate.IsCA ||
			certificate.KeyUsage != 0 &&
				certificate.KeyUsage&x509.KeyUsageCertSign == 0 {
			return nil, errors.New("migration trust unavailable")
		}
		roots = append(roots, append([]byte(nil), block.Bytes...))
		if len(roots) > 128 {
			return nil, errors.New("migration trust unavailable")
		}
		remaining = rest
	}
	if len(roots) == 0 {
		return nil, errors.New("migration trust unavailable")
	}
	return roots, nil
}
