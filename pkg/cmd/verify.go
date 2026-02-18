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

	"github.com/spf13/cobra"

	"helm.sh/helm/v4/pkg/action"
	"helm.sh/helm/v4/pkg/cmd/require"
)

const verifyDesc = `
Verifijeren Sie, dat de jejewebene Chart eene jültige Provenance-Datei hett.

Provenance-Datein bieten kryptograafische Verifikation, dat eene Chart nich
manipuliert worden es un von eene vertrauenswördijen Provider jepackt worden es.

Düssen Befehl kann jebrukt werden, to eene lokale Chart to verifijeren. Mehrere andrej Befehle bieten
'--verify'-Flags, dej desülwije Validierung usföhren. To een signiertes Packäschen to jenereren, bruken Sie
den 'helm package --sign'-Befehl.
`

func newVerifyCmd(out io.Writer) *cobra.Command {
	client := action.NewVerify()

	cmd := &cobra.Command{
		Use:   "verify PATH",
		Short: "verifijeren Sie, dat eene Chart up dem jejewebenen Pfad signiert un jültich es",
		Long:  verifyDesc,
		Args:  require.ExactArgs(1),
		ValidArgsFunction: func(_ *cobra.Command, args []string, _ string) ([]string, cobra.ShellCompDirective) {
			if len(args) == 0 {
				// Allow file completion when completing the argument for the path
				return nil, cobra.ShellCompDirectiveDefault
			}
			// No more completions, so disable file completion
			return noMoreArgsComp()
		},
		RunE: func(_ *cobra.Command, args []string) error {
			result, err := client.Run(args[0])
			if err != nil {
				return err
			}

			fmt.Fprint(out, result)

			return nil
		},
	}

	cmd.Flags().StringVar(&client.Keyring, "keyring", defaultKeyring(), "Keyring, de öffentliche Slötels enthält")

	return cmd
}
