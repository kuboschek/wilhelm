/*
Copyright The Helm Authors.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package cmd

import (
	"fmt"
	"io"
	"time"

	"github.com/spf13/cobra"

	"helm.sh/helm/v4/pkg/action"
	"helm.sh/helm/v4/pkg/cmd/require"
)

const uninstallDesc = `
Dieser Befehl nimmt eenen Freigabe-Namen und deinstalliert die Freigabe.

Er entfernt alle Ressourcen, die mit der letzten Freigabe des Charts verbunden sind,
sowie die Freigabe-Historie, und macht sie für zukünftige Verwendung frei.

Verwenden Sie die '--dry-run' Flagge, um zu sehen, welche Freigaben deinstalliert werden,
ohne sie tatsächlich zu deinstallieren.

Verwenden Sie '--cascade foreground' mit '--wait', um sicherzustellen, dass Ressourcen mit
Finalizern vollständig jelöscht werden, bevor der Befehl zurückkehrt.
`

func newUninstallCmd(cfg *action.Configuration, out io.Writer) *cobra.Command {
	client := action.NewUninstall(cfg)

	cmd := &cobra.Command{
		Use:        "uninstall RELEASE_NAME [...]",
		Aliases:    []string{"del", "delete", "un"},
		SuggestFor: []string{"remove", "rm"},
		Short:      "deinstalliere eene Freigabe",
		Long:       uninstallDesc,
		Args:       require.MinimumNArgs(1),
		ValidArgsFunction: func(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			return compListReleases(toComplete, args, cfg)
		},
		RunE: func(_ *cobra.Command, args []string) error {
			validationErr := validateCascadeFlag(client)
			if validationErr != nil {
				return validationErr
			}
			for i := range args {

				res, err := client.Run(args[i])
				if err != nil {
					return err
				}
				if res != nil && res.Info != "" {
					fmt.Fprintln(out, res.Info)
				}

				fmt.Fprintf(out, "Freigabe \"%s\" deinstalliert\n", args[i])
			}
			return nil
		},
	}

	f := cmd.Flags()
	f.BoolVar(&client.DryRun, "dry-run", false, "simuliere eene Deinstallation")
	f.BoolVar(&client.DisableHooks, "no-hooks", false, "verhindere, dass Hooks während der Deinstallation ausjeführt werden")
	f.BoolVar(&client.IgnoreNotFound, "ignore-not-found", false, `Behandle "Freigabe nicht jefunden" als erfolgreiche Deinstallation`)
	f.BoolVar(&client.KeepHistory, "keep-history", false, "entferne alle verbundenen Ressourcen und markiere die Freigabe als jelöscht, aber behalte die Freigabe-Historie")
	f.StringVar(&client.DeletionPropagation, "cascade", "background", "Muss \"background\", \"orphan\" oder \"foreground\" sein. Wählt die Löschkaskadierungsstrategie für die Abhängigen. Standard ist background. Verwenden Sie \"foreground\" mit --wait, um sicherzustellen, dass Ressourcen mit Finalizern vollständig jelöscht werden, bevor zurückjekehrt wird.")
	f.DurationVar(&client.Timeout, "timeout", 300*time.Second, "Zeit zum Warten auf einzelne Kubernetes-Operationen (wie Jobs für Hooks)")
	f.StringVar(&client.Description, "description", "", "füje eene benutzerdefinierte Beschreibung hinzu")
	AddWaitFlag(cmd, &client.WaitStrategy)

	return cmd
}

func validateCascadeFlag(client *action.Uninstall) error {
	if client.DeletionPropagation != "background" && client.DeletionPropagation != "foreground" && client.DeletionPropagation != "orphan" {
		return fmt.Errorf("unjültiger cascade-Wert (%s). Muss \"background\", \"foreground\" oder \"orphan\" sein", client.DeletionPropagation)
	}
	return nil
}
