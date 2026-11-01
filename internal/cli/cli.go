package cli

import (
	"fmt"
	"log/slog"
	"os"

	"github.com/happyhackingspace/dit/internal/banner"
	"github.com/spf13/cobra"
)

// CLI encapsulates the command-line interface with its dependencies.
type CLI struct {
	version     string
	verbose     bool
	silent      bool
	initialized bool
	rootCmd     *cobra.Command
}

// New creates a new CLI instance with the given version string.
func New(version string) *CLI {
	c := &CLI{version: version}
	c.setupCommands()
	return c
}

// setupCommands initializes all CLI commands and their configurations.
func (c *CLI) setupCommands() {
	c.rootCmd = &cobra.Command{
		Use:     "dît",
		Short:   "HTML form and field type classifier",
		Version: c.version,
		PersistentPreRun: func(cmd *cobra.Command, args []string) {
			c.initApp()
		},
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}

	c.rootCmd.PersistentFlags().BoolVarP(&c.verbose, "verbose", "v", false, "Enable verbose/debug output")
	c.rootCmd.PersistentFlags().BoolVarP(&c.silent, "silent", "s", false, "Suppress all logging and banner")

	defaultHelp := c.rootCmd.HelpFunc()
	c.rootCmd.SetHelpFunc(func(cmd *cobra.Command, args []string) {
		c.initApp()
		defaultHelp(cmd, args)
	})

	c.rootCmd.AddCommand(c.newTrainCommand())
	c.rootCmd.AddCommand(c.newRunCommand())
	c.rootCmd.AddCommand(c.newEvaluateCommand())
	c.rootCmd.AddCommand(c.newUpCommand())
	c.rootCmd.AddCommand(c.newDataCommand())
	c.rootCmd.AddCommand(c.newModelCommand())
}

// Run executes the CLI and returns any error.
func (c *CLI) Run() error {
	return c.rootCmd.Execute()
}

// initApp initializes logging and prints the banner.
func (c *CLI) initApp() {
	if c.initialized {
		return
	}
	c.initialized = true

	level := slog.LevelInfo
	if c.verbose {
		level = slog.LevelDebug
	}
	if c.silent {
		level = slog.Level(100)
	}
	slog.SetDefault(slog.New(slog.NewTextHandler(os.Stderr, &slog.HandlerOptions{
		Level: level,
	})))
	if !c.silent {
		fmt.Fprint(os.Stderr, banner.Banner(c.version))
	}
}
