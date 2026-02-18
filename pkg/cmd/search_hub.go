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
	"log/slog"
	"strings"

	"github.com/gosuri/uitable"
	"github.com/spf13/cobra"

	"helm.sh/helm/v4/internal/monocular"
	"helm.sh/helm/v4/pkg/cli/output"
)

const searchHubDesc = `
Söök na Helm-Charts in de Artifact Hub oder jue eigene Hub-Instanz.

Artifact Hub is eene webbasierte Anwendung, de et möglich macht, Packete un Konfiguratschonen
för CNCF-Projekte to finnen, to installieren un to publizieren, inklusiv öffentlich verfögbare
verteilte Charts Helm-Charts. Et is een Cloud Native Computing Foundation Sandbox-Projekt.
Jie könnt de Hub dorchsöken ünner https://artifacthub.io/

Dat [KEYWORD]-Argument akzeptiert entweder eenen Sökbegriffsstring oder eenen zitierten String
met rich query options. För de Dokumentatschon vun rich query options, söök ünner
https://artifacthub.github.io/hub/api/?urls.primaryName=Monocular%20compatible%20search%20API#/Monocular/get_api_chartsvc_v1_charts_search

Fröhere Versionen vun Helm hemm eene Instanz vun Monocular als standard 'endpoint' je-bruukt,
daröm is Artifact Hub för Rückwärtskompatibilität met de Monocular-Sök-API kompatibel.
Ebenso mutt, wenn de 'endpoint'-Flagge je-sett ward, de angeben Endpoint ook eenen Monocular-
kompatiblen Sök-API-Endpoint implementieren. Merkt, dat wenn een Monocular-Instanz als 'endpoint'
angeben ward, rich queries nich ünnerstitzt warden. För API-Details, söök ünner https://github.com/helm/monocular
`

type searchHubOptions struct {
	searchEndpoint string
	maxColWidth    uint
	outputFormat   output.Format
	listRepoURL    bool
	failOnNoResult bool
}

func newSearchHubCmd(out io.Writer) *cobra.Command {
	o := &searchHubOptions{}

	cmd := &cobra.Command{
		Use:   "hub [KEYWORD]",
		Short: "na Charts in de Artifact Hub oder jue eigene Hub-Instanz söken",
		Long:  searchHubDesc,
		RunE: func(_ *cobra.Command, args []string) error {
			return o.run(out, args)
		},
	}

	f := cmd.Flags()
	f.StringVar(&o.searchEndpoint, "endpoint", "https://hub.helm.sh", "Hub-Instanz, de na Charts je-fraagt ward")
	f.UintVar(&o.maxColWidth, "max-col-width", 50, "maximale Spaltenbreedte för Utgawetabell")
	f.BoolVar(&o.listRepoURL, "list-repo-url", false, "Chart-Repository-URL utjewen")
	f.BoolVar(&o.failOnNoResult, "fail-on-no-result", false, "Söök feilt, wenn keene Resultate je-funnen warden")

	bindOutputFlag(cmd, &o.outputFormat)

	return cmd
}

func (o *searchHubOptions) run(out io.Writer, args []string) error {
	c, err := monocular.New(o.searchEndpoint)
	if err != nil {
		return fmt.Errorf("kann keene Verbindung to %q herstellen: %w", o.searchEndpoint, err)
	}

	q := strings.Join(args, " ")
	results, err := c.Search(q)
	if err != nil {
		slog.Debug("search failed", slog.Any("error", err))
		return fmt.Errorf("kann keene Söök jegen %q durchföhren", o.searchEndpoint)
	}

	return o.outputFormat.Write(out, newHubSearchWriter(results, o.searchEndpoint, o.maxColWidth, o.listRepoURL, o.failOnNoResult))
}

type hubChartRepo struct {
	URL  string `json:"url"`
	Name string `json:"name"`
}

type hubChartElement struct {
	URL         string       `json:"url"`
	Version     string       `json:"version"`
	AppVersion  string       `json:"app_version"`
	Description string       `json:"description"`
	Repository  hubChartRepo `json:"repository"`
}

type hubSearchWriter struct {
	elements       []hubChartElement
	columnWidth    uint
	listRepoURL    bool
	failOnNoResult bool
}

func newHubSearchWriter(results []monocular.SearchResult, endpoint string, columnWidth uint, listRepoURL, failOnNoResult bool) *hubSearchWriter {
	var elements []hubChartElement
	for _, r := range results {
		// Backwards compatibility for Monocular
		url := endpoint + "/charts/" + r.ID

		// Check for artifactHub compatibility
		if r.ArtifactHub.PackageURL != "" {
			url = r.ArtifactHub.PackageURL
		}

		elements = append(elements, hubChartElement{url, r.Relationships.LatestChartVersion.Data.Version, r.Relationships.LatestChartVersion.Data.AppVersion, r.Attributes.Description, hubChartRepo{URL: r.Attributes.Repo.URL, Name: r.Attributes.Repo.Name}})
	}
	return &hubSearchWriter{elements, columnWidth, listRepoURL, failOnNoResult}
}

func (h *hubSearchWriter) WriteTable(out io.Writer) error {
	if len(h.elements) == 0 {
		// Fail if no results found and --fail-on-no-result is enabled
		if h.failOnNoResult {
			return fmt.Errorf("keene Resultate je-funnen")
		}

		_, err := out.Write([]byte("Keene Resultate je-funnen\n"))
		if err != nil {
			return fmt.Errorf("kann Resultate nich schriewen: %s", err)
		}
		return nil
	}
	table := uitable.New()
	table.MaxColWidth = h.columnWidth

	if h.listRepoURL {
		table.AddRow("URL", "CHART-VERSION", "APP-VERSION", "BESCHRIEWUNG", "REPO-URL")
	} else {
		table.AddRow("URL", "CHART-VERSION", "APP-VERSION", "BESCHRIEWUNG")
	}

	for _, r := range h.elements {
		if h.listRepoURL {
			table.AddRow(r.URL, r.Version, r.AppVersion, r.Description, r.Repository.URL)
		} else {
			table.AddRow(r.URL, r.Version, r.AppVersion, r.Description)
		}
	}
	return output.EncodeTable(out, table)
}

func (h *hubSearchWriter) WriteJSON(out io.Writer) error {
	return h.encodeByFormat(out, output.JSON)
}

func (h *hubSearchWriter) WriteYAML(out io.Writer) error {
	return h.encodeByFormat(out, output.YAML)
}

func (h *hubSearchWriter) encodeByFormat(out io.Writer, format output.Format) error {
	// Fail if no results found and --fail-on-no-result is enabled
	if len(h.elements) == 0 && h.failOnNoResult {
		return fmt.Errorf("keene Resultate je-funnen")
	}

	// Initialize the array so no results returns an empty array instead of null
	chartList := make([]hubChartElement, 0, len(h.elements))

	for _, r := range h.elements {
		chartList = append(chartList, hubChartElement{r.URL, r.Version, r.AppVersion, r.Description, r.Repository})
	}

	switch format {
	case output.JSON:
		return output.EncodeJSON(out, chartList)
	case output.YAML:
		return output.EncodeYAML(out, chartList)
	default:
		// Because this is a non-exported function and only called internally by
		// WriteJSON and WriteYAML, we shouldn't get invalid types
		return nil
	}

}
