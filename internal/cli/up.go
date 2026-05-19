package cli

import (
	"context"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"path/filepath"

	"github.com/creativeprojects/go-selfupdate"
	"github.com/happyhackingspace/dit"
	"github.com/spf13/cobra"
)

func (c *CLI) newUpCommand() *cobra.Command {
	return &cobra.Command{
		Use:   "up",
		Short: "Self-update to the latest version",
		RunE: func(cmd *cobra.Command, args []string) error {
			return c.selfUpdate()
		},
	}
}

func (c *CLI) selfUpdate() error {
	v := c.version
	if v == "dev" {
		v = "0.0.0"
	}

	updater, err := selfupdate.NewUpdater(selfupdate.Config{})
	if err != nil {
		return err
	}

	latest, found, err := updater.DetectLatest(context.Background(), selfupdate.ParseSlug("happyhackingspace/dit"))
	if err != nil {
		return fmt.Errorf("detect latest version: %w", err)
	}
	if !found {
		return fmt.Errorf("no release found")
	}

	if latest.LessOrEqual(v) {
		fmt.Printf("Already up to date (%s)\n", c.version)
		return nil
	}

	slog.Info("Updating", "from", c.version, "to", latest.Version())

	exe, err := os.Executable()
	if err != nil {
		return err
	}

	if err := updater.UpdateTo(context.Background(), latest, exe); err != nil {
		return fmt.Errorf("update: %w", err)
	}

	fmt.Printf("Updated to %s\n", latest.Version())

	// Also refresh cached model
	modelDest := filepath.Join(dit.ModelDir(), "model.json")
	if _, err := os.Stat(modelDest); err == nil {
		slog.Info("Updating cached model")
		modelResp, err := http.Get(dit.ModelURL)
		if err == nil {
			defer func() { _ = modelResp.Body.Close() }()
			if modelResp.StatusCode == http.StatusOK {
				if err := os.MkdirAll(filepath.Dir(modelDest), 0755); err == nil {
					if f, err := os.Create(modelDest); err == nil {
						_, _ = io.Copy(f, modelResp.Body)
						_ = f.Close()
						slog.Info("Model updated")
					}
				}
			}
		}
	}

	return nil
}
