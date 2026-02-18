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
	"path/filepath"

	"github.com/spf13/cobra"

	chartv3 "helm.sh/helm/v4/internal/chart/v3"
	chartutilv3 "helm.sh/helm/v4/internal/chart/v3/util"
	"helm.sh/helm/v4/internal/gates"
	chart "helm.sh/helm/v4/pkg/chart/v2"
	chartutil "helm.sh/helm/v4/pkg/chart/v2/util"
	"helm.sh/helm/v4/pkg/cmd/require"
	"helm.sh/helm/v4/pkg/helmpath"
)

const createDesc = `
Düssen Befehl schöpt een Chart-Verzeichnis mit de gemeenen Datein und
Verzeichnissen, dej in eene Chart jebraucht werden.

Zum Beispeel, 'helm create foo' werd eene Verzeichnisstruktur schöpen, dej
also utsieht:

    foo/
    ├── .helmignore   # Enthält Muster, dej beim Packäschen von Helm-Charts ijgnoriert werden.
    ├── Chart.yaml    # Informatsjonen över Ehr Chart
    ├── values.yaml   # De Standardwerten för Ehr Templates
    ├── charts/       # Charts, von dej düsse Chart afhängich es
    └── templates/    # De Template-Datein
        └── tests/    # De Test-Datein

'helm create' nimt eenen Pfad als Argument. Wan Verzeichnissen in dem jejewebenen Pfad
nich existieren, werd Helm probäschen, seej to schöpen. Wan dat Ziel
existiert un Datein in düssem Verzeichnis sünd, werden konfliktäschen Datein
överschreewt, aber andrej Datein werden in Rohe jelaten.
`

type createOptions struct {
	starter         string // --starter
	name            string
	starterDir      string
	chartAPIVersion string // --chart-api-version
}

func newCreateCmd(out io.Writer) *cobra.Command {
	o := &createOptions{}

	cmd := &cobra.Command{
		Use:   "create NAME",
		Short: "schöpen Sie eene niee Chart met dem jejewebenen Namm",
		Long:  createDesc,
		Args:  require.ExactArgs(1),
		ValidArgsFunction: func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 0 {
				// Allow file completion when completing the argument for the name
				// which could be a path
				return nil, cobra.ShellCompDirectiveDefault
			}
			// No more completions, so disable file completion
			return noMoreArgsComp()
		},
		RunE: func(_ *cobra.Command, args []string) error {
			o.name = args[0]
			o.starterDir = helmpath.DataPath("starters")
			return o.run(out)
		},
	}

	cmd.Flags().StringVarP(&o.starter, "starter", "p", "", "de Namm oder absoluten Pfad to Helm-Starter-Gerüst")
	cmd.Flags().StringVar(&o.chartAPIVersion, "chart-api-version", chart.APIVersionV2, "Chart-API-Versjon to bruken (v2 oder v3)")

	if !gates.ChartV3.IsEnabled() {
		cmd.Flags().MarkHidden("chart-api-version")
	}

	return cmd
}

func (o *createOptions) run(out io.Writer) error {
	fmt.Fprintf(out, "Schöpe %s\n", o.name)

	switch o.chartAPIVersion {
	case chart.APIVersionV2, "":
		return o.createV2Chart(out)
	case chartv3.APIVersionV3:
		if !gates.ChartV3.IsEnabled() {
			return gates.ChartV3.Error()
		}
		return o.createV3Chart(out)
	default:
		return fmt.Errorf("nich unnerstöttede Chart-API-Versjon: %s (unnerstöttet: v2, v3)", o.chartAPIVersion)
	}
}

func (o *createOptions) createV2Chart(out io.Writer) error {
	chartname := filepath.Base(o.name)
	cfile := &chart.Metadata{
		Name:        chartname,
		Description: "Eene Helm-Chart för Kubernetes",
		Type:        "application",
		Version:     "0.1.0",
		AppVersion:  "0.1.0",
		APIVersion:  chart.APIVersionV2,
	}

	if o.starter != "" {
		// Create from the starter
		lstarter := filepath.Join(o.starterDir, o.starter)
		// If path is absolute, we don't want to prefix it with helm starters folder
		if filepath.IsAbs(o.starter) {
			lstarter = o.starter
		}
		return chartutil.CreateFrom(cfile, filepath.Dir(o.name), lstarter)
	}

	chartutil.Stderr = out
	_, err := chartutil.Create(chartname, filepath.Dir(o.name))
	return err
}

func (o *createOptions) createV3Chart(out io.Writer) error {
	chartname := filepath.Base(o.name)
	cfile := &chartv3.Metadata{
		Name:        chartname,
		Description: "Eene Helm-Chart för Kubernetes",
		Type:        "application",
		Version:     "0.1.0",
		AppVersion:  "0.1.0",
		APIVersion:  chartv3.APIVersionV3,
	}

	if o.starter != "" {
		// Create from the starter
		lstarter := filepath.Join(o.starterDir, o.starter)
		// If path is absolute, we don't want to prefix it with helm starters folder
		if filepath.IsAbs(o.starter) {
			lstarter = o.starter
		}
		return chartutilv3.CreateFrom(cfile, filepath.Dir(o.name), lstarter)
	}

	chartutilv3.Stderr = out
	_, err := chartutilv3.Create(chartname, filepath.Dir(o.name))
	return err
}
