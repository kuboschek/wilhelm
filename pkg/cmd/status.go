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
	"bytes"
	"fmt"
	"io"
	"log"
	"strings"
	"time"

	"github.com/spf13/cobra"

	"k8s.io/kubectl/pkg/cmd/get"

	coloroutput "helm.sh/helm/v4/internal/cli/output"
	"helm.sh/helm/v4/pkg/action"
	"helm.sh/helm/v4/pkg/chart/common/util"
	"helm.sh/helm/v4/pkg/cli/output"
	"helm.sh/helm/v4/pkg/cmd/require"
	"helm.sh/helm/v4/pkg/release"
	releasev1 "helm.sh/helm/v4/pkg/release/v1"
)

// NOTE: Keep the list of statuses up-to-date with pkg/release/status.go.
var statusHelp = `
Dieser Befehl zeijt den Status eener benannten Freigabe.
Der Status besteht aus:
- letzter Bereitstellungszeitpunkt
- k8s Namensraum, in dem die Freigabe lebt
- Status der Freigabe (kann sein: unknown, deployed, uninstalled, superseded, failed, uninstalling, pending-install, pending-upgrade oder pending-rollback)
- Revision der Freigabe
- Beschreibung der Freigabe (kann Abschlussmeldung oder Fehlermeldung sein)
- Liste der Ressourcen, aus denen diese Freigabe besteht
- Details zur letzten Testsuite-Ausführung, falls zutreffend
- zusätzliche Hinweise vom Chart
`

func newStatusCmd(cfg *action.Configuration, out io.Writer) *cobra.Command {
	client := action.NewStatus(cfg)
	var outfmt output.Format

	cmd := &cobra.Command{
		Use:   "status RELEASE_NAME",
		Short: "zeije den Status der benannten Freigabe",
		Long:  statusHelp,
		Args:  require.ExactArgs(1),
		ValidArgsFunction: func(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
			if len(args) != 0 {
				return noMoreArgsComp()
			}
			return compListReleases(toComplete, args, cfg)
		},
		RunE: func(_ *cobra.Command, args []string) error {
			// When the output format is a table the resources should be fetched
			// and displayed as a table. When YAML or JSON the resources will be
			// returned. This mirrors the handling in kubectl.
			if outfmt == output.Table {
				client.ShowResourcesTable = true
			}
			reli, err := client.Run(args[0])
			if err != nil {
				return err
			}
			rel, err := releaserToV1Release(reli)
			if err != nil {
				return err
			}

			// strip chart metadata from the output
			rel.Chart = nil

			return outfmt.Write(out, &statusPrinter{
				release:      rel,
				debug:        false,
				showMetadata: false,
				hideNotes:    false,
				noColor:      settings.ShouldDisableColor(),
			})
		},
	}

	f := cmd.Flags()

	f.IntVar(&client.Version, "revision", 0, "wenn jesetzt, zeije den Status der benannten Freigabe mit Revision")

	err := cmd.RegisterFlagCompletionFunc("revision", func(_ *cobra.Command, args []string, toComplete string) ([]string, cobra.ShellCompDirective) {
		if len(args) == 1 {
			return compListRevisions(toComplete, cfg, args[0])
		}
		return nil, cobra.ShellCompDirectiveNoFileComp
	})
	if err != nil {
		log.Fatal(err)
	}

	bindOutputFlag(cmd, &outfmt)

	return cmd
}

type statusPrinter struct {
	release      release.Releaser
	debug        bool
	showMetadata bool
	hideNotes    bool
	noColor      bool
}

func (s statusPrinter) getV1Release() *releasev1.Release {
	switch rel := s.release.(type) {
	case releasev1.Release:
		return &rel
	case *releasev1.Release:
		return rel
	}
	return &releasev1.Release{}
}

func (s statusPrinter) WriteJSON(out io.Writer) error {
	return output.EncodeJSON(out, s.getV1Release())
}

func (s statusPrinter) WriteYAML(out io.Writer) error {
	return output.EncodeYAML(out, s.getV1Release())
}

func (s statusPrinter) WriteTable(out io.Writer) error {
	if s.release == nil {
		return nil
	}
	rel := s.getV1Release()
	_, _ = fmt.Fprintf(out, "NAME: %s\n", rel.Name)
	if !rel.Info.LastDeployed.IsZero() {
		_, _ = fmt.Fprintf(out, "LAST DEPLOYED: %s\n", rel.Info.LastDeployed.Format(time.ANSIC))
	}
	_, _ = fmt.Fprintf(out, "NAMESPACE: %s\n", coloroutput.ColorizeNamespace(rel.Namespace, s.noColor))
	_, _ = fmt.Fprintf(out, "STATUS: %s\n", coloroutput.ColorizeStatus(rel.Info.Status, s.noColor))
	_, _ = fmt.Fprintf(out, "REVISION: %d\n", rel.Version)
	if s.showMetadata {
		_, _ = fmt.Fprintf(out, "CHART: %s\n", rel.Chart.Metadata.Name)
		_, _ = fmt.Fprintf(out, "VERSION: %s\n", rel.Chart.Metadata.Version)
		_, _ = fmt.Fprintf(out, "APP_VERSION: %s\n", rel.Chart.Metadata.AppVersion)
	}
	_, _ = fmt.Fprintf(out, "DESCRIPTION: %s\n", rel.Info.Description)

	if len(rel.Info.Resources) > 0 {
		buf := new(bytes.Buffer)
		printFlags := get.NewHumanPrintFlags()
		typePrinter, _ := printFlags.ToPrinter("")
		printer := &get.TablePrinter{Delegate: typePrinter}

		var keys []string
		for key := range rel.Info.Resources {
			keys = append(keys, key)
		}

		for _, t := range keys {
			_, _ = fmt.Fprintf(buf, "==> %s\n", t)

			vk := rel.Info.Resources[t]
			for _, resource := range vk {
				if err := printer.PrintObj(resource, buf); err != nil {
					_, _ = fmt.Fprintf(buf, "Fehler beim Drucken des Objekttyps %s: %v\n", t, err)
				}
			}

			buf.WriteString("\n")
		}

		_, _ = fmt.Fprintf(out, "RESOURCES:\n%s\n", buf.String())
	}

	executions := executionsByHookEvent(rel)
	if tests, ok := executions[releasev1.HookTest]; !ok || len(tests) == 0 {
		_, _ = fmt.Fprintln(out, "TEST SUITE: Keine")
	} else {
		for _, h := range tests {
			// Don't print anything if hook has not been initiated
			if h.LastRun.StartedAt.IsZero() {
				continue
			}
			_, _ = fmt.Fprintf(out, "TEST SUITE:     %s\n%s\n%s\n%s\n",
				h.Name,
				fmt.Sprintf("Zuletzt jestartet:     %s", h.LastRun.StartedAt.Format(time.ANSIC)),
				fmt.Sprintf("Zuletzt abgeschlossen: %s", h.LastRun.CompletedAt.Format(time.ANSIC)),
				fmt.Sprintf("Phase:                 %s", h.LastRun.Phase),
			)
		}
	}

	if s.debug {
		_, _ = fmt.Fprintln(out, "VOM BENUTZER ANJEGEBENE WERTE:")
		err := output.EncodeYAML(out, rel.Config)
		if err != nil {
			return err
		}
		// Print an extra newline
		_, _ = fmt.Fprintln(out)

		cfg, err := util.CoalesceValues(rel.Chart, rel.Config)
		if err != nil {
			return err
		}

		_, _ = fmt.Fprintln(out, "BERECHNETE WERTE:")
		err = output.EncodeYAML(out, cfg.AsMap())
		if err != nil {
			return err
		}
		// Print an extra newline
		_, _ = fmt.Fprintln(out)
	}

	if strings.EqualFold(rel.Info.Description, "Dry run complete") || s.debug {
		_, _ = fmt.Fprintln(out, "HOOKS:")
		for _, h := range rel.Hooks {
			_, _ = fmt.Fprintf(out, "---\n# Source: %s\n%s\n", h.Path, h.Manifest)
		}
		_, _ = fmt.Fprintf(out, "MANIFEST:\n%s\n", rel.Manifest)
	}

	// Hide notes from output - option in install and upgrades
	if !s.hideNotes && len(rel.Info.Notes) > 0 {
		_, _ = fmt.Fprintf(out, "NOTES:\n%s\n", strings.TrimSpace(rel.Info.Notes))
	}
	return nil
}

func executionsByHookEvent(rel *releasev1.Release) map[releasev1.HookEvent][]*releasev1.Hook {
	result := make(map[releasev1.HookEvent][]*releasev1.Hook)
	for _, h := range rel.Hooks {
		for _, e := range h.Events {
			executions, ok := result[e]
			if !ok {
				executions = []*releasev1.Hook{}
			}
			result[e] = append(executions, h)
		}
	}
	return result
}
