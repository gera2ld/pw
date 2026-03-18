package cli

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"pw/internal/secrets"
	"sort"

	"github.com/spf13/cobra"
)

func NewRootCommand(version string, sm *secrets.SecretManager) *cobra.Command {
	cmd := &cobra.Command{
		Use:     "pw",
		Short:   "Minimalist CLI Secret Manager",
		Version: version,
	}

	cmd.AddCommand(newRunCommand(sm))
	cmd.AddCommand(newRmCommand(sm))
	cmd.AddCommand(newImportCommand(sm))
	cmd.AddCommand(newExportCommand(sm))
	cmd.AddCommand(newLsCommand(sm))
	cmd.AddCommand(newMvCommand(sm))
	cmd.AddCommand(newEditCommand(sm))
	cmd.AddCommand(newRcpCommand(sm))
	cmd.AddCommand(newReindexCommand(sm))
	cmd.AddCommand(newShowCommand(sm))

	return cmd
}

func newRunCommand(sm *secrets.SecretManager) *cobra.Command {
	var export bool

	cmd := &cobra.Command{
		Use:   "run <id>... -- <command>",
		Short: "Run command with secrets injected",
		Long: `Run a command with secrets loaded from the specified IDs.
Use -- to separate IDs from the command.`,
		Args: cobra.MinimumNArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			sepIndex := -1
			for i, arg := range args {
				if arg == "--" {
					sepIndex = i
					break
				}
			}

			if sepIndex == -1 {
				return errors.New("missing '--' separator between IDs and command")
			}

			ids := args[:sepIndex]
			commandArgs := args[sepIndex+1:]
			if len(commandArgs) == 0 {
				return errors.New("no command provided after '--'")
			}

			envVars := sm.GetSecrets(ids)

			if export {
				for key, value := range envVars {
					fmt.Printf("%s=%s\n", key, value)
				}
				return nil
			}

			env := os.Environ()
			for key, value := range envVars {
				env = append(env, fmt.Sprintf("%s=%s", key, value))
			}

			command := commandArgs[0]
			cmdExec := exec.Command(command, commandArgs[1:]...)
			cmdExec.Env = env
			cmdExec.Stdout = os.Stdout
			cmdExec.Stderr = os.Stderr
			cmdExec.Stdin = os.Stdin

			return cmdExec.Run()
		},
	}

	cmd.Flags().BoolVar(&export, "export", false, "Print environment variables to stdout")

	return cmd
}

func newRmCommand(sm *secrets.SecretManager) *cobra.Command {
	return &cobra.Command{
		Use:   "rm <id>",
		Short: "Delete the physical file and update index",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			err := sm.DeleteSecret(id)
			return err
		},
	}
}

func newImportCommand(sm *secrets.SecretManager) *cobra.Command {
	var conflict string

	cmd := &cobra.Command{
		Use:   "import <source>",
		Short: "Import data from a directory",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			source := args[0]

			ids, err := sm.ImportTree(source, "", conflict)
			if err != nil {
				return fmt.Errorf("failed to import data from %s: %w", source, err)
			}

			fmt.Printf("Successfully imported %d ids from %s\n", len(ids), source)
			return nil
		},
	}

	cmd.Flags().StringVar(&conflict, "conflict", "abort", "Conflict resolution: abort, skip, or overwrite")

	return cmd
}

func newExportCommand(sm *secrets.SecretManager) *cobra.Command {
	var outDir string
	var prefix string

	cmd := &cobra.Command{
		Use:   "export",
		Short: "Export all data to a directory",
		RunE: func(cmd *cobra.Command, args []string) error {
			if outDir == "" {
				outDir = "vault-export"
			}

			ids, err := sm.ExportTree(outDir, prefix)
			if err != nil {
				return fmt.Errorf("failed to export data: %w", err)
			}

			fmt.Printf("Exported %d ids to %s\n", len(ids), outDir)
			return nil
		},
	}

	cmd.Flags().StringVarP(&outDir, "outDir", "o", "vault-export", "Output directory")
	cmd.Flags().StringVar(&prefix, "prefix", "", "Filter the ids by the prefix and strip it when writing to files")

	return cmd
}

func newLsCommand(sm *secrets.SecretManager) *cobra.Command {
	return &cobra.Command{
		Use:   "ls",
		Short: "List all indexed __ids",
		RunE: func(cmd *cobra.Command, args []string) error {
			ids, err := sm.ListSecrets()
			if err != nil {
				return err
			}
			sort.Strings(ids)
			for _, id := range ids {
				fmt.Println(id)
			}
			return nil
		},
	}
}

func newMvCommand(sm *secrets.SecretManager) *cobra.Command {
	return &cobra.Command{
		Use:   "mv <id> <new_id>",
		Short: "Update the __id field and refresh index",
		Args:  cobra.ExactArgs(2),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]
			newID := args[1]
			parsed, err := sm.GetSecret(id)
			if err != nil {
				return err
			}
			parsed.Data["__id"] = newID
			return sm.SetSecret(id, parsed)
		},
	}
}

func newEditCommand(sm *secrets.SecretManager) *cobra.Command {
	return &cobra.Command{
		Use:   "edit <id>",
		Short: "Edit the value of a secret with $EDITOR",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]

			editor := os.Getenv("EDITOR")
			if editor == "" {
				return errors.New("$EDITOR is not set")
			}

			parsed, err := sm.GetSecret(id)
			var oldValue string
			if err != nil {
				fmt.Println("Editing new secret")
				oldValue = fmt.Sprintf("__id: %s\n", id)
			} else {
				if parsed.Data == nil {
					parsed.Data = make(map[string]any)
				}
				value, err := sm.FormatValue(parsed)
				if err != nil {
					return fmt.Errorf("failed to format value: %w", err)
				}
				oldValue = value
			}

			safeID := sm.SanitizeID(id)
			tempFile, err := os.CreateTemp("", fmt.Sprintf("%s-*.yml", safeID))
			if err != nil {
				return fmt.Errorf("failed to create temporary file: %w", err)
			}
			defer os.Remove(tempFile.Name())

			if _, err := tempFile.WriteString(oldValue); err != nil {
				return fmt.Errorf("failed to write to temporary file: %w", err)
			}
			tempFile.Close()

			cmdExec := exec.Command(editor, tempFile.Name())
			cmdExec.Stdout = os.Stdout
			cmdExec.Stderr = os.Stderr
			cmdExec.Stdin = os.Stdin

			if err := cmdExec.Run(); err != nil {
				return fmt.Errorf("failed to open editor: %w", err)
			}

			newValueBytes, err := os.ReadFile(tempFile.Name())
			if err != nil {
				return fmt.Errorf("failed to read temporary file: %w", err)
			}
			newValue := string(newValueBytes)

			if newValue == "" {
				fmt.Println("No changes made.")
				return nil
			}

			parsed, err = sm.ParseRawValue(newValue)
			if err != nil {
				return fmt.Errorf("failed to parse new value: %w\nMake sure to include __id: %s", err, id)
			}

			newID := parsed.Data["__id"].(string)

			if newValue == oldValue && newID == id {
				fmt.Println("No changes made.")
				return nil
			}

			if err := sm.SetSecret(id, parsed); err != nil {
				return fmt.Errorf("failed to save updated value: %w", err)
			}

			if newID != id {
				fmt.Printf("Renamed %s to %s\n", id, newID)
			} else {
				fmt.Println("Updated id:", id)
			}
			return nil
		},
	}
}

func newRcpCommand(sm *secrets.SecretManager) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "rcp",
		Short: "Manage age recipients (public keys)",
	}

	cmd.AddCommand(&cobra.Command{
		Use:   "ls",
		Short: "List all recipients",
		RunE: func(cmd *cobra.Command, args []string) error {
			recipients := sm.UserConfig.Data.Recipients
			for _, recipient := range recipients {
				fmt.Println(recipient)
			}
			return nil
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "add <recipient>",
		Short: "Add a recipient",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			recipient := args[0]
			return sm.UserConfig.AddRecipient(recipient)
		},
	})

	cmd.AddCommand(&cobra.Command{
		Use:   "rm <recipient>",
		Short: "Remove a recipient",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			recipient := args[0]
			return sm.UserConfig.RemoveRecipient(recipient)
		},
	})

	return cmd
}

func newReindexCommand(sm *secrets.SecretManager) *cobra.Command {
	return &cobra.Command{
		Use:   "reindex",
		Short: "Rebuild index for all data",
		RunE: func(cmd *cobra.Command, args []string) error {
			return sm.BuildIndex()
		},
	}
}

func newShowCommand(sm *secrets.SecretManager) *cobra.Command {
	return &cobra.Command{
		Use:   "show <id>",
		Short: "Decrypt and print the full content to stdout",
		Args:  cobra.ExactArgs(1),
		RunE: func(cmd *cobra.Command, args []string) error {
			id := args[0]

			parsed, err := sm.GetSecret(id)
			if err != nil {
				return fmt.Errorf("failed to retrieve secret: %w", err)
			}

			if parsed.Data == nil {
				parsed.Data = make(map[string]any)
			}

			value, err := sm.FormatValue(parsed)
			if err != nil {
				return fmt.Errorf("failed to format value: %w", err)
			}

			fmt.Println(value)
			return nil
		},
	}
}
