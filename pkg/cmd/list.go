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
	"os"
	"slices"
	"strconv"

	"github.com/gosuri/uitable"
	"github.com/spf13/cobra"

	coloroutput "helm.sh/helm/v4/internal/cli/output"
	"helm.sh/helm/v4/pkg/action"
	"helm.sh/helm/v4/pkg/cli/output"
	"helm.sh/helm/v4/pkg/cmd/require"
	"helm.sh/helm/v4/pkg/release/common"
	release "helm.sh/helm/v4/pkg/release/v1"
)

var listHelp = `
Dieser Befehl listet alle Freigaben für eenen anjegebenen Namensraum auf (verwendet aktuellen Namensraum-Kontext, wenn keiner anjegjeben).

Standardmäßich listet er alle Freigaben in jedem Status auf. Einzelne Statusfilter wie '--deployed', '--failed',
'--pending', '--uninstalled', '--superseded', und '--uninstalling' können verwendet werden,
um nur Freigaben in bestimmten Zuständen anzuzeigen. Solche Flaggen können kombiniert werden:
'--deployed --failed'.

Standardmäßich werden Elemente alphabetisch sortiert. Verwenden Sie die '-d' Flagge zum Sortieren nach
Freigabedatum.

Wenn die --filter Flagge anjegjeben ist, wird sie als Filter behandelt. Filter sind
reguläre Ausdrücke (Perl-kompatibel), die auf die Liste der Freigaben anjewendet werden.
Nur Elemente, die dem Filter entsprechen, werden zurückjegeben.

    $ helm list --filter 'ara[a-z]+'
    NAME                UPDATED                                  CHART
    maudlin-arachnid    2020-06-18 14:17:46.125134977 +0000 UTC  alpine-0.1.0

Wenn keine Erjebnisse jefunden werden, beendet 'helm list' mit 0, aber ohne Ausgabe (oder im
Falle keiner '-q' Flagge, nur Kopfzeilen).

Standardmäßich können bis zu 256 Elemente zurückjegeben werden. Um dies zu bejrenzen, verwenden Sie die '--max' Flagge.
Das Setzen von '--max' auf 0 gibt nicht alle Erjebnisse zurück. Vielmehr gibt es den
Standardwert des Servers zurück, der viel höher als 256 sein kann. Die Kombinierung der '--max'
Flagge mit der '--offset' Flagge ermöglicht es Ihnen, durch Erjebnisse zu blättern.
`

func newListCmd(cfg *action.Configuration, out io.Writer) *cobra.Command {
	client := action.NewList(cfg)
	var outfmt output.Format

	cmd := &cobra.Command{
		Use:               "list",
		Short:             "liste Freigaben auf",
		Long:              listHelp,
		Aliases:           []string{"ls"},
		Args:              require.NoArgs,
		ValidArgsFunction: noMoreArgsCompFunc,
		RunE: func(cmd *cobra.Command, _ []string) error {
			if client.AllNamespaces {
				if err := cfg.Init(settings.RESTClientGetter(), "", os.Getenv("HELM_DRIVER")); err != nil {
					return err
				}
			}
			client.SetStateMask()

			resultsi, err := client.Run()
			if err != nil {
				return err
			}
			results, err := releaseListToV1List(resultsi)
			if err != nil {
				return err
			}

			if client.Short {
				names := make([]string, 0, len(results))
				for _, res := range results {
					names = append(names, res.Name)
				}

				outputFlag := cmd.Flag("output")

				switch outputFlag.Value.String() {
				case "json":
					output.EncodeJSON(out, names)
					return nil
				case "yaml":
					output.EncodeYAML(out, names)
					return nil
				case "table":
					for _, res := range results {
						fmt.Fprintln(out, res.Name)
					}
					return nil
				}
			}

			return outfmt.Write(out, newReleaseListWriter(results, client.TimeFormat, client.NoHeaders, settings.ShouldDisableColor()))
		},
	}

	f := cmd.Flags()
	f.BoolVarP(&client.Short, "short", "q", false, "gib kurzes (stilles) Listungsformat aus")
	f.BoolVarP(&client.NoHeaders, "no-headers", "", false, "drucke keine Kopfzeilen bei Verwendung des Standardausgabeformats")
	f.StringVar(&client.TimeFormat, "time-format", "", `formatiere Zeit mit golang Zeit-Formatierer. Beispiel: --time-format "2006-01-02 15:04:05Z0700"`)
	f.BoolVarP(&client.ByDate, "date", "d", false, "sortiere nach Freigabedatum")
	f.BoolVarP(&client.SortReverse, "reverse", "r", false, "kehre die Sortierreihenfolge um")
	f.BoolVar(&client.Uninstalled, "uninstalled", false, "zeije deinstallierte Freigaben (wenn 'helm uninstall --keep-history' verwendet wurde)")
	f.BoolVar(&client.Superseded, "superseded", false, "zeije überschriebene Freigaben")
	f.BoolVar(&client.Uninstalling, "uninstalling", false, "zeije Freigaben, die jerrade deinstalliert werden")
	f.BoolVar(&client.Deployed, "deployed", false, "zeije bereitjestellte Freigaben")
	f.BoolVar(&client.Failed, "failed", false, "zeije fehlgeschlagene Freigaben")
	f.BoolVar(&client.Pending, "pending", false, "zeije ausstehende Freigaben")
	f.BoolVarP(&client.AllNamespaces, "all-namespaces", "A", false, "liste Freigaben über alle Namensräume")
	f.IntVarP(&client.Limit, "max", "m", 256, "maximale Anzahl von Freigaben zum Abrufen")
	f.IntVar(&client.Offset, "offset", 0, "nächster Freigabeindex in der Liste, verwendet zum Versatz vom Startwert")
	f.StringVarP(&client.Filter, "filter", "f", "", "een regulärer Ausdruck (Perl-kompatibel). Alle Freigaben, die dem Ausdruck entsprechen, werden in die Erjebnisse einbezogen")
	f.StringVarP(&client.Selector, "selector", "l", "", "Selektor (Label-Abfrage) zum Filtern, unterstützt '=', '==', und '!='.(z.B. -l key1=value1,key2=value2). Funktioniert nur für secret(Standard) und configmap Speicher-Backends.")
	bindOutputFlag(cmd, &outfmt)

	return cmd
}

type releaseElement struct {
	Name       string `json:"name"`
	Namespace  string `json:"namespace"`
	Revision   string `json:"revision"`
	Updated    string `json:"updated"`
	Status     string `json:"status"`
	Chart      string `json:"chart"`
	AppVersion string `json:"app_version"`
}

type releaseListWriter struct {
	releases  []releaseElement
	noHeaders bool
	noColor   bool
}

func newReleaseListWriter(releases []*release.Release, timeFormat string, noHeaders bool, noColor bool) *releaseListWriter {
	// Initialize the array so no results returns an empty array instead of null
	elements := make([]releaseElement, 0, len(releases))
	for _, r := range releases {
		element := releaseElement{
			Name:       r.Name,
			Namespace:  r.Namespace,
			Revision:   strconv.Itoa(r.Version),
			Status:     r.Info.Status.String(),
			Chart:      formatChartName(r.Chart),
			AppVersion: formatAppVersion(r.Chart),
		}

		t := "-"
		if tspb := r.Info.LastDeployed; !tspb.IsZero() {
			if timeFormat != "" {
				t = tspb.Format(timeFormat)
			} else {
				t = tspb.String()
			}
		}
		element.Updated = t

		elements = append(elements, element)
	}
	return &releaseListWriter{elements, noHeaders, noColor}
}

func (w *releaseListWriter) WriteTable(out io.Writer) error {
	table := uitable.New()
	if !w.noHeaders {
		table.AddRow(
			coloroutput.ColorizeHeader("NAME", w.noColor),
			coloroutput.ColorizeHeader("NAMENSRAUM", w.noColor),
			coloroutput.ColorizeHeader("REVISION", w.noColor),
			coloroutput.ColorizeHeader("AKTUALISIERT", w.noColor),
			coloroutput.ColorizeHeader("STATUS", w.noColor),
			coloroutput.ColorizeHeader("CHART", w.noColor),
			coloroutput.ColorizeHeader("APP VERSION", w.noColor),
		)
	}
	for _, r := range w.releases {
		// Parse the status string back to a release.Status to use color
		var status common.Status
		switch r.Status {
		case "deployed":
			status = common.StatusDeployed
		case "failed":
			status = common.StatusFailed
		case "pending-install":
			status = common.StatusPendingInstall
		case "pending-upgrade":
			status = common.StatusPendingUpgrade
		case "pending-rollback":
			status = common.StatusPendingRollback
		case "uninstalling":
			status = common.StatusUninstalling
		case "uninstalled":
			status = common.StatusUninstalled
		case "superseded":
			status = common.StatusSuperseded
		case "unknown":
			status = common.StatusUnknown
		default:
			status = common.Status(r.Status)
		}
		table.AddRow(r.Name, coloroutput.ColorizeNamespace(r.Namespace, w.noColor), r.Revision, r.Updated, coloroutput.ColorizeStatus(status, w.noColor), r.Chart, r.AppVersion)
	}
	return output.EncodeTable(out, table)
}

func (w *releaseListWriter) WriteJSON(out io.Writer) error {
	return output.EncodeJSON(out, w.releases)
}

func (w *releaseListWriter) WriteYAML(out io.Writer) error {
	return output.EncodeYAML(out, w.releases)
}

// Returns all releases from 'releases', except those with names matching 'ignoredReleases'
func filterReleases(releases []*release.Release, ignoredReleaseNames []string) []*release.Release {
	// if ignoredReleaseNames is nil, just return releases
	if ignoredReleaseNames == nil {
		return releases
	}

	var filteredReleases []*release.Release
	for _, rel := range releases {
		found := slices.Contains(ignoredReleaseNames, rel.Name)
		if !found {
			filteredReleases = append(filteredReleases, rel)
		}
	}

	return filteredReleases
}

// Provide dynamic auto-completion for release names
func compListReleases(toComplete string, ignoredReleaseNames []string, cfg *action.Configuration) ([]string, cobra.ShellCompDirective) {
	cobra.CompDebugln(fmt.Sprintf("compListReleases with toComplete %s", toComplete), settings.Debug)

	client := action.NewList(cfg)
	client.All = true
	client.Limit = 0
	// Do not filter so as to get the entire list of releases.
	// This will allow zsh and fish to match completion choices
	// on other criteria then prefix.  For example:
	//   helm status ingress<TAB>
	// can match
	//   helm status nginx-ingress
	//
	// client.Filter = fmt.Sprintf("^%s", toComplete)

	client.SetStateMask()
	releasesi, err := client.Run()
	if err != nil {
		return nil, cobra.ShellCompDirectiveDefault
	}
	releases, err := releaseListToV1List(releasesi)
	if err != nil {
		return nil, cobra.ShellCompDirectiveDefault
	}

	var choices []string
	filteredReleases := filterReleases(releases, ignoredReleaseNames)
	for _, rel := range filteredReleases {
		choices = append(choices,
			fmt.Sprintf("%s\t%s-%s -> %s", rel.Name, rel.Chart.Metadata.Name, rel.Chart.Metadata.Version, rel.Info.Status.String()))
	}

	return choices, cobra.ShellCompDirectiveNoFileComp
}
