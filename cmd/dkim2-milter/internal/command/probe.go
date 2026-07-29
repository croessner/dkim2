package command

import (
	"os"
	"path/filepath"
	"syscall"

	"github.com/croessner/dkim2/cmd/dkim2-milter/internal/config"
	"github.com/spf13/cobra"
)

// newProbeCommand constructs the config-bound non-mutating socket probe.
func newProbeCommand(load func(string) (config.Snapshot, error)) *cobra.Command {
	var configPath string
	command := &cobra.Command{
		Use:           probeCommandName,
		Short:         "Check the configured owned Unix socket",
		Args:          cobra.NoArgs,
		SilenceUsage:  true,
		SilenceErrors: true,
		RunE: func(*cobra.Command, []string) error {
			return runProbe(configPath, load)
		},
	}
	command.Flags().StringVar(&configPath, "config", "", "absolute configuration document path")
	_ = command.MarkFlagRequired("config")
	return command
}

// runProbe derives the only permitted socket from validated configuration.
func runProbe(configPath string, load func(string) (config.Snapshot, error)) error {
	if load == nil || !filepath.IsAbs(configPath) || filepath.Clean(configPath) != configPath {
		return errCommandRuntime
	}
	snapshot, err := load(configPath)
	if err != nil {
		return errCommandRuntime
	}
	return probeSocket(snapshot.Socket())
}

// probeSocket validates the owned socket inode without opening a Milter session.
func probeSocket(socket string) error {
	if !filepath.IsAbs(socket) || filepath.Clean(socket) != socket {
		return errCommandRuntime
	}
	info, err := os.Lstat(socket)
	if err != nil || info.Mode()&os.ModeSocket == 0 || info.Mode()&os.ModeSymlink != 0 {
		return errCommandRuntime
	}
	if info.Mode().Perm()&0o007 != 0 {
		return errCommandRuntime
	}
	stat, ok := info.Sys().(*syscall.Stat_t)
	if !ok || int(stat.Uid) != os.Geteuid() || stat.Nlink != 1 {
		return errCommandRuntime
	}
	return nil
}
