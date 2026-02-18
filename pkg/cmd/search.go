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
)

const searchDesc = `
Search beed de Möglichkeit, na Helm-Charts in de verschiedenen Steden to söken,
wo se je-spieckerd warden könnt, inklusiv de Artifact Hub un Repositories, de jie je-addiert hemm.
Bruukt Search-Subkommandos, öm verschiedene Steden na Charts to söken.
`

func newSearchCmd(out io.Writer) *cobra.Command {

	cmd := &cobra.Command{
		Use:   "search [keyword]",
		Short: "na eenen Sökbegriff in Charts söken",
		Long:  searchDesc,
	}

	cmd.AddCommand(newSearchHubCmd(out))
	cmd.AddCommand(newSearchRepoCmd(out))

	return cmd
}
