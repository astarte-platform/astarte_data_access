#
# This file is part of Astarte.
#
# Copyright 2024 SECO Mind Srl
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
# See the License for the specific language governing permissions and
# limitations under the License.
#

defmodule Astarte.DataAccess.Keyspace do
  require Logger
  alias Astarte.DataAccess.XandraUtils

  def keyspace_existing?(keyspace_name) do
    case XandraUtils.run_without_realm_validation(
           keyspace_name,
           fn conn, keyspace_name ->
             do_keyspace_existing?(conn, keyspace_name)
           end
         ) do
      result when is_boolean(result) ->
        {:ok, result}

      {:error, reason} ->
        Logger.warning("Cannot select if keyspace existing: #{inspect(reason)}.",
          tag: "keyspace_existing?",
          keyspace: keyspace_name
        )

        {:error, reason}
    end
  end

  defp do_keyspace_existing?(conn, keyspace_name) do
    query = """
    SELECT
      COUNT(*)
    FROM
      system_schema.keyspaces
    WHERE
      keyspace_name = :keyspace_name
    """

    params = %{
      keyspace_name: keyspace_name
    }

    with {:ok, page} <- XandraUtils.retrieve_page(conn, query, params),
         {:ok, %{count: count}} = Enum.fetch(page, 0) do
      not (count == 0)
    end
  end
end
