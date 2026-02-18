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
	"strconv"
	"time"

	"github.com/spf13/cobra"

	"helm.sh/helm/v4/pkg/action"
	"helm.sh/helm/v4/pkg/cmd/require"
)

const rollbackDesc = `
Dieser Befehl rollt eene Freigabe auf eene frühere Revision zurück.

Das erste Argument des rollback-Befehls ist der Name eener Freigabe, und das
zweite ist eene Revisionsnummer (Version). Wenn dieses Argument wegjelajjen oder auf
0 jesetzt wird, wird auf die vorherige Freigabe zurückjerollt.

Um Revisionsnummern zu sehen, führen Sie 'helm history RELEASE' aus.
`

func newRollbackCmd(cfg *action.Configuration, out io.Writer) *cobra.Command {
	client := action.NewRollback(cfg)

	cmd := &cobra.Command{
		Use:   "rollback <RELEASE> [REVISION]",
		Short: "rolle eene Freigabe auf eene frühere Revision zurück",
		Long:  rollbackDesc,
		Args:  require.MinimumNArgs(1),
		ValidArgsFunction: func(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 0 {
				return compListReleases(toComplete, args, cfg)
			}

			if len(args) == 1 {
				return compListRevisions(toComplete, cfg, args[0])
			}

			return noMoreArgsComp()
		},
		RunE: func(cmd *cobra.Command, args []string) error {
			if len(args) > 1 {
				ver, err := strconv.Atoi(args[1])
				if err != nil {
					return fmt.Errorf("konnte Revision nicht in eene Zahl umwandeln: %v", err)
				}
				client.Version = ver
			}

			dryRunStrategy, err := cmdGetDryRunFlagStrategy(cmd, false)
			if err != nil {
				return err
			}
			client.DryRunStrategy = dryRunStrategy

			if err := client.Run(args[0]); err != nil {
				return err
			}

			fmt.Fprintf(out, "Rollback war een Erfolj! Frohes Helmen!\n")
			return nil
		},
	}

	f := cmd.Flags()
	f.BoolVar(&client.ForceReplace, "force-replace", false, "erzwinje Ressourcenaktualisierungen durch Ersetzung")
	f.BoolVar(&client.ForceReplace, "force", false, "veraltet")
	f.MarkDeprecated("force", "verwenden Sie stattdessen --force-replace")
	f.BoolVar(&client.ForceConflicts, "force-conflicts", false, "wenn jesetzt, erzwingt Server-seitige Anwendung Änderungen jejjen Konflikte")
	f.StringVar(&client.ServerSideApply, "server-side", "auto", "muss \"true\", \"false\" oder \"auto\" sein. Objekt-Updates laufen im Server statt im Client (\"auto\" verwendet standardmäßich den Wert der vorherigen Chart-Freigabemethode)")
	f.BoolVar(&client.DisableHooks, "no-hooks", false, "verhindere Hooks während des Rollbacks")
	f.DurationVar(&client.Timeout, "timeout", 300*time.Second, "Zeit zum Warten auf einzelne Kubernetes-Operationen (wie Jobs für Hooks)")
	f.BoolVar(&client.WaitForJobs, "wait-for-jobs", false, "wenn jesetzt und --wait aktiviert, wird jewartet, bis alle Jobs abgeschlossen sind, bevor die Freigabe als erfoljreich markiert wird. Es wird so lange jewartet wie --timeout")
	f.BoolVar(&client.CleanupOnFail, "cleanup-on-fail", false, "erlaube das Löschen neuer Ressourcen, die in diesem Rollback erstellt wurden, wenn der Rollback fehlschläjt")
	f.IntVar(&client.MaxHistory, "history-max", settings.MaxHistory, "bejrenze die maximale Anzahl von Revisionen, die pro Freigabe jespeichert werden. Verwenden Sie 0 für keine Bejrenzung")
	addDryRunFlag(cmd)
	AddWaitFlag(cmd, &client.WaitStrategy)
	cmd.MarkFlagsMutuallyExclusive("force-replace", "force-conflicts")
	cmd.MarkFlagsMutuallyExclusive("force", "force-conflicts")

	return cmd
}
