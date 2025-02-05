#
# This file is part of Astarte.
#
# Copyright 2023-2024 SECO Mind Srl
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

defmodule Astarte.DataAccess.XandraUtils do
  alias Astarte.Core.Realm
  alias Astarte.Core.CQLUtils
  alias Astarte.DataAccess.Config

  require Logger

  @cluster_default_name :astarte_data_access_xandra

  def verify_realm_name(realm_name) do
    if Realm.valid_name?(realm_name) do
      :ok
    else
      Logger.warning("Invalid realm name.",
        tag: "verify_realm_name",
        realm: realm_name
      )

      {:error, :invalid_realm_name}
    end
  end

  def build_keyspace_name!(keyspace_name) do
    CQLUtils.realm_name_to_keyspace_name(keyspace_name, Config.astarte_instance_id!())
  end

  def run_without_realm_validation(realm_name, fun, opts \\ []) when is_function(fun) do
    keyspace_name = build_keyspace_name!(realm_name)

    case do_run(fun, keyspace_name, opts) do
      {:ok, result} ->
        {:ok, result}

      {:error, %Xandra.Error{} = err} ->
        _ = Logger.warning("Database error: #{inspect(err)}.", tag: "database_error")
        {:error, :database_error}

      {:error, %Xandra.ConnectionError{} = err} ->
        _ =
          Logger.warning("Database connection error: #{inspect(err)}.",
            tag: "database_connection_error"
          )

        {:error, :database_connection_error}

      other ->
        other
    end
  end

  @spec run(binary(), (Xandra.Connection, binary() -> any)) :: any() | {:error, atom()}
  @spec run(binary(), (Xandra.Connection, binary() -> any), keyword()) :: any() | {:error, atom()}
  def run(realm_name, fun, opts \\ []) do
    with :ok <- verify_realm_name(realm_name),
         {:ok, result} <- run_without_realm_validation(realm_name, fun, opts) do
      {:ok, result}
    end
  end

  def execute_query(conn, statement), do: execute_query(conn, statement, %{}, [])

  def execute_query(conn, statement, opts) when is_list(opts),
    do: execute_query(conn, statement, %{}, opts)

  def execute_query(conn, statement, params) when is_map(params),
    do: execute_query(conn, statement, params, [])

  def execute_query(conn, query, params, opts) when is_map(params) and is_list(opts) do
    opts = Keyword.merge(default_query_opts(), opts)

    with {:ok, prepared} <- prepare_query(conn, query, opts) do
      case Xandra.execute(conn, prepared, params, opts) do
        {:ok, result} ->
          {:ok, result}

        {:error, %Xandra.Error{} = reason} ->
          _ = Logger.warning("Database error while executing: #{inspect(reason)}")
          {:error, :database_error}

        {:error, %Xandra.ConnectionError{} = reason} ->
          _ = Logger.warning("Database connection error while executing: #{inspect(reason)}")
          {:error, :database_connection_error}
      end
    end
  end

  def retrieve_page(conn, query), do: retrieve_page(conn, query, %{}, [])

  def retrieve_page(conn, query, opts) when is_list(opts),
    do: retrieve_page(conn, query, %{}, opts)

  def retrieve_page(conn, query, params) when is_map(params),
    do: retrieve_page(conn, query, params, [])

  def retrieve_page(conn, query, params, opts) when is_map(params) and is_list(opts) do
    with {:ok, %Xandra.Page{} = page} <- execute_query(conn, query, params, opts) do
      {:ok, page}
    end
  end

  defp do_run(fun, keyspace, opts) when is_function(fun) do
    Xandra.Cluster.run(
      @cluster_default_name,
      Keyword.merge([timeout: 60_000], opts),
      &fun.(&1, keyspace)
    )
  end

  defp prepare_query(conn, statement, opts) do
    case Xandra.prepare(conn, statement, opts) do
      {:ok, %Xandra.Prepared{} = prepared} ->
        {:ok, prepared}

      {:error, %Xandra.Error{} = reason} ->
        _ = Logger.warning("Database error while preparing query: #{inspect(reason)}")
        {:error, :database_error}

      {:error, %Xandra.ConnectionError{} = reason} ->
        _ = Logger.warning("Database connection error while preparing query: #{inspect(reason)}")
        {:error, :database_connection_error}
    end
  end

  defp default_query_opts() do
    [uuid_format: :binary, timestamp_format: :integer]
  end
end
