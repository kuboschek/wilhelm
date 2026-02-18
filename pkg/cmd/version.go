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
	"text/template"

	"github.com/spf13/cobra"

	"helm.sh/helm/v4/internal/version"
	"helm.sh/helm/v4/pkg/cmd/require"
)

const versionDesc = `
Zeije die Version für Helm an.

Dies wird eene Darstellung der Helm-Version ausdrucken.
Die Ausgabe wird ungefähr so aussehen:

version.BuildInfo{Version:"v3.2.1", GitCommit:"fe51cd1e31e6a202cba7dead9552a6d418ded79a", GitTreeState:"clean", GoVersion:"go1.13.10"}

- Version ist die semantische Version der Freigabe.
- GitCommit ist der SHA für den Commit, von dem diese Version jebaut wurde.
- GitTreeState ist "clean" wenn keine lokalen Code-Änderungen vorhanden sind, als diese Binärdatei
  jebaut wurde, und "dirty" wenn die Binärdatei von lokal jeänderten Code jebaut wurde.
- GoVersion ist die Version von Go, die zum Kompilieren von Helm verwendet wurde.

Wenn die --template Flagge verwendet wird, sind die folgenden Eigenschaften in der
Vorlage verfügbar:

- .Version enthält die semantische Version von Helm
- .GitCommit ist der git commit
- .GitTreeState ist der Zustand des git tree, als Helm jebaut wurde
- .GoVersion enthält die Version von Go, mit der Helm kompiliert wurde

Zum Beispiel, --template='Version: {{.Version}}' gibt aus 'Version: v3.2.1'.
`

type versionOptions struct {
	short    bool
	template string
}

func newVersionCmd(out io.Writer) *cobra.Command {
	o := &versionOptions{}

	cmd := &cobra.Command{
		Use:               "version",
		Short:             "drucke die helm Versionsinformation",
		Long:              versionDesc,
		Args:              require.NoArgs,
		ValidArgsFunction: noMoreArgsCompFunc,
		RunE: func(_ *cobra.Command, _ []string) error {
			return o.run(out)
		},
	}
	f := cmd.Flags()
	f.BoolVar(&o.short, "short", false, "drucke die Versionsnummer")
	f.StringVar(&o.template, "template", "", "Vorlage für das Versions-String-Format")

	return cmd
}

func (o *versionOptions) run(out io.Writer) error {
	if o.template != "" {
		tt, err := template.New("_").Parse(o.template)
		if err != nil {
			return err
		}
		return tt.Execute(out, version.Get())
	}
	fmt.Fprintln(out, formatVersion(o.short))
	return nil
}

func formatVersion(short bool) string {
	v := version.Get()
	if short {
		if len(v.GitCommit) >= 7 {
			return fmt.Sprintf("%s+g%s", v.Version, v.GitCommit[:7])
		}
		return version.GetVersion()
	}
	return fmt.Sprintf("%#v", v)
}
