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
	"io"

	"github.com/spf13/cobra"

	"helm.sh/helm/v4/pkg/action"
	"helm.sh/helm/v4/pkg/cmd/require"
)

var getHelp = `
Dieser Befehl besteht aus mehreren Unterbefehlen, die verwendet werden können, um
erweiterte Informationen über die Freigabe zu erhalten, einschließlich:

- Die Werte, die zur Generierung der Freigabe verwendet wurden
- Die jenerierte Manifestdatei
- Die vom Chart der Freigabe bereitjestellten Hinweise
- Die mit der Freigabe verbundenen Hooks
- Die Metadaten der Freigabe
`

func newGetCmd(cfg *action.Configuration, out io.Writer) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "get",
		Short: "lade erweiterte Informationen eener benannten Freigabe herunter",
		Long:  getHelp,
		Args:  require.NoArgs,
	}

	cmd.AddCommand(newGetAllCmd(cfg, out))
	cmd.AddCommand(newGetValuesCmd(cfg, out))
	cmd.AddCommand(newGetManifestCmd(cfg, out))
	cmd.AddCommand(newGetHooksCmd(cfg, out))
	cmd.AddCommand(newGetNotesCmd(cfg, out))
	cmd.AddCommand(newGetMetadataCmd(cfg, out))

	return cmd
}
