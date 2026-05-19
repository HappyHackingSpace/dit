package cli

import (
	"archive/tar"
	"compress/gzip"
	"fmt"
	"io"
	"log/slog"
	"net/http"
	"os"
	"os/exec"
	"path/filepath"
	"strings"

	"github.com/happyhackingspace/dit"
	"github.com/spf13/cobra"
)

const hfDataURL = "https://huggingface.co/datasets/happyhackingspace/dit/resolve/main/data.tar.gz"

func (c *CLI) newDataCommand() *cobra.Command {
	dataCmd := &cobra.Command{
		Use:   "data",
		Short: "Manage training data and model files (download/upload via Hugging Face)",
		Run: func(cmd *cobra.Command, args []string) {
			_ = cmd.Help()
		},
	}

	var downloadDataFolder string
	downloadCmd := &cobra.Command{
		Use:   "download",
		Short: "Download training data and model from Hugging Face",
		Example: `  dit data download
  dit data download --data-folder data`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return dataDownload(downloadDataFolder)
		},
	}
	downloadCmd.Flags().StringVar(&downloadDataFolder, "data-folder", "data", "Destination folder for training data")

	var uploadDataFolder string
	uploadCmd := &cobra.Command{
		Use:   "upload",
		Short: "Upload training data and model to Hugging Face",
		Example: `  dit data upload
  dit data upload --data-folder data`,
		RunE: func(cmd *cobra.Command, args []string) error {
			return dataUpload(uploadDataFolder)
		},
	}
	uploadCmd.Flags().StringVar(&uploadDataFolder, "data-folder", "data", "Source folder for training data")

	dataCmd.AddCommand(downloadCmd, uploadCmd)
	return dataCmd
}

func dataDownload(dataFolder string) error {
	slog.Info("Downloading training data", "url", hfDataURL)
	resp, err := http.Get(hfDataURL)
	if err != nil {
		return fmt.Errorf("download data: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("download data: HTTP %d", resp.StatusCode)
	}

	if err := os.RemoveAll(dataFolder); err != nil {
		return fmt.Errorf("remove existing %s: %w", dataFolder, err)
	}

	gr, err := gzip.NewReader(resp.Body)
	if err != nil {
		return fmt.Errorf("gzip reader: %w", err)
	}
	defer func() { _ = gr.Close() }()

	tr := tar.NewReader(gr)
	count := 0
	for {
		hdr, err := tr.Next()
		if err == io.EOF {
			break
		}
		if err != nil {
			return fmt.Errorf("read tar: %w", err)
		}

		target := hdr.Name
		if strings.HasPrefix(target, "data/") {
			target = dataFolder + target[len("data"):]
		}
		target = filepath.Clean(target)

		switch hdr.Typeflag {
		case tar.TypeDir:
			if err := os.MkdirAll(target, 0755); err != nil {
				return fmt.Errorf("create dir %s: %w", target, err)
			}
		case tar.TypeReg:
			if err := os.MkdirAll(filepath.Dir(target), 0755); err != nil {
				return fmt.Errorf("create parent dir: %w", err)
			}
			f, err := os.Create(target)
			if err != nil {
				return fmt.Errorf("create file %s: %w", target, err)
			}
			if _, err := io.Copy(f, tr); err != nil {
				_ = f.Close()
				return fmt.Errorf("write file %s: %w", target, err)
			}
			_ = f.Close()
			count++
		}
	}
	slog.Info("Training data extracted", "files", count, "folder", dataFolder)

	slog.Info("Downloading model", "url", dit.ModelURL)
	modelResp, err := http.Get(dit.ModelURL)
	if err != nil {
		return fmt.Errorf("download model: %w", err)
	}
	defer func() { _ = modelResp.Body.Close() }()
	if modelResp.StatusCode != http.StatusOK {
		return fmt.Errorf("download model: HTTP %d", modelResp.StatusCode)
	}

	mf, err := os.Create("model.json")
	if err != nil {
		return fmt.Errorf("create model.json: %w", err)
	}
	written, err := io.Copy(mf, modelResp.Body)
	if err != nil {
		_ = mf.Close()
		return fmt.Errorf("write model.json: %w", err)
	}
	_ = mf.Close()
	slog.Info("Model downloaded", "size", fmt.Sprintf("%.1fMB", float64(written)/1024/1024))

	return nil
}

func dataUpload(dataFolder string) error {
	if _, err := exec.LookPath("huggingface-cli"); err != nil {
		return fmt.Errorf("huggingface-cli not found in PATH; install with: pip install huggingface_hub")
	}

	tarPath := "data.tar.gz"
	slog.Info("Creating archive", "source", dataFolder, "dest", tarPath)

	tf, err := os.Create(tarPath)
	if err != nil {
		return fmt.Errorf("create %s: %w", tarPath, err)
	}

	gw := gzip.NewWriter(tf)
	tw := tar.NewWriter(gw)

	err = filepath.Walk(dataFolder, func(path string, info os.FileInfo, err error) error {
		if err != nil {
			return err
		}
		hdr, err := tar.FileInfoHeader(info, "")
		if err != nil {
			return err
		}
		hdr.Name = path
		if err := tw.WriteHeader(hdr); err != nil {
			return err
		}
		if info.IsDir() {
			return nil
		}
		f, err := os.Open(path)
		if err != nil {
			return err
		}
		defer func() { _ = f.Close() }()
		_, err = io.Copy(tw, f)
		return err
	})
	if err != nil {
		_ = tw.Close()
		_ = gw.Close()
		_ = tf.Close()
		return fmt.Errorf("create archive: %w", err)
	}
	if err := tw.Close(); err != nil {
		_ = gw.Close()
		_ = tf.Close()
		return fmt.Errorf("close tar: %w", err)
	}
	if err := gw.Close(); err != nil {
		_ = tf.Close()
		return fmt.Errorf("close gzip: %w", err)
	}
	_ = tf.Close()
	slog.Info("Archive created", "path", tarPath)

	slog.Info("Uploading data.tar.gz")
	cmd := exec.Command("huggingface-cli", "upload", "happyhackingspace/dit", tarPath, "data.tar.gz", "--repo-type", "dataset")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("upload data.tar.gz: %w", err)
	}

	slog.Info("Uploading data folder")
	cmd = exec.Command("huggingface-cli", "upload", "happyhackingspace/dit", dataFolder, "data/", "--repo-type", "dataset")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("upload data folder: %w", err)
	}

	if _, err := os.Stat("model.json"); err == nil {
		slog.Info("Uploading model.json")
		cmd = exec.Command("huggingface-cli", "upload", "happyhackingspace/dit", "model.json", "model.json", "--repo-type", "dataset")
		cmd.Stdout = os.Stdout
		cmd.Stderr = os.Stderr
		if err := cmd.Run(); err != nil {
			return fmt.Errorf("upload model.json: %w", err)
		}
	}

	slog.Info("Upload complete")
	return nil
}
