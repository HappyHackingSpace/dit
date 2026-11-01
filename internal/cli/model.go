package cli

import (
	"fmt"
	"io"
	"log/slog"
	"os"

	"github.com/happyhackingspace/dit"
	"github.com/spf13/cobra"
)

func (c *CLI) newModelCommand() *cobra.Command {
	modelCmd := &cobra.Command{
		Use:   "model",
		Short: "Manage the pretrained model cache",
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}

	var force bool
	pullCmd := &cobra.Command{
		Use:   "pull",
		Short: "Download the pretrained model to the local cache",
		Example: `  dit model pull
  dit model pull --force`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return modelPull(os.Stdout, dit.DefaultModelPath(), force)
		},
	}
	pullCmd.Flags().BoolVar(&force, "force", false, "Re-download even if the model is already cached")

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show the cached model's path, size, and SHA-256 checksum",
		RunE: func(cmd *cobra.Command, args []string) error {
			return modelStatus(os.Stdout, dit.DefaultModelPath())
		},
	}

	rmCmd := &cobra.Command{
		Use:   "rm",
		Short: "Remove the cached model",
		RunE: func(cmd *cobra.Command, args []string) error {
			return modelRm(os.Stdout, dit.DefaultModelPath())
		},
	}

	modelCmd.AddCommand(pullCmd, statusCmd, rmCmd)
	return modelCmd
}

// modelPull downloads the pretrained model to dest unless it is already
// present; force re-downloads unconditionally.
func modelPull(w io.Writer, dest string, force bool) error {
	if !force {
		if _, err := os.Stat(dest); err == nil {
			if _, err := fmt.Fprintf(w, "Model already cached at %s (use --force to re-download)\n", dest); err != nil {
				return err
			}
			return modelStatus(w, dest)
		}
	}
	slog.Info("Downloading model", "url", dit.ModelURL, "dest", dest, "size", "~93MB")
	if err := dit.Download(dest); err != nil {
		return err
	}
	return modelStatus(w, dest)
}

// modelStatus prints the model file's path, existence, size, and SHA-256
// checksum.
func modelStatus(w io.Writer, path string) error {
	info, err := os.Stat(path)
	if os.IsNotExist(err) {
		_, werr := fmt.Fprintf(w, "path:    %s\nexists:  false\n", path)
		return werr
	}
	if err != nil {
		return fmt.Errorf("stat model: %w", err)
	}
	sum, err := dit.FileSHA256(path)
	if err != nil {
		return fmt.Errorf("checksum model: %w", err)
	}
	_, err = fmt.Fprintf(w, "path:    %s\nexists:  true\nsize:    %.1f MB (%d bytes)\nsha256:  %s\n",
		path, float64(info.Size())/1024/1024, info.Size(), sum)
	return err
}

// modelRm removes the cached model file if it exists.
func modelRm(w io.Writer, path string) error {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		_, werr := fmt.Fprintf(w, "No cached model at %s\n", path)
		return werr
	}
	if err := os.Remove(path); err != nil {
		return fmt.Errorf("remove model: %w", err)
	}
	_, err := fmt.Fprintf(w, "Removed %s\n", path)
	return err
}
