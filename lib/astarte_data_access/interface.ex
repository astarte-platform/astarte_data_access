#
# This file is part of Astarte.
#
# Copyright 2018 - 2023 SECO Mind Srl
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

defmodule Astarte.DataAccess.Interface do
  require Logger
  alias Astarte.Core.InterfaceDescriptor
  alias Astarte.DataAccess.Repo
  alias Astarte.DataAccess.Realms.Interface
  import Ecto.Query

  @interface_row_default_selector [
    :name,
    :major_version,
    :minor_version,
    :interface_id,
    :type,
    :ownership,
    :aggregation,
    :storage,
    :storage_type,
    :automaton_transitions,
    :automaton_accepting_states
  ]

  @spec retrieve_interface_row(String.t(), String.t(), integer, keyword()) ::
          {:ok, keyword()} | {:error, atom}
  def retrieve_interface_row(realm, interface_name, major_version, opts \\ []) do
    query =
      from Interface,
        where: [name: ^interface_name, major_version: ^major_version]

    query =
      if opts[:include_docs], do: query, else: select(query, ^@interface_row_default_selector)

    Repo.fetch_one(query, error: :interface_not_found, prefix: realm)
  end

  @spec fetch_interface_descriptor(String.t(), String.t(), non_neg_integer) ::
          {:ok, %InterfaceDescriptor{}} | {:error, atom}
  def fetch_interface_descriptor(realm_name, interface_name, major_version) do
    with {:ok, interface_row} <-
           retrieve_interface_row(realm_name, interface_name, major_version) do
      InterfaceDescriptor.from_db_result(interface_row)
    end
  end

  @spec check_if_interface_exists(String.t(), String.t(), non_neg_integer) ::
          :ok | {:error, atom}
  def check_if_interface_exists(realm, interface_name, major_version) do
    query = from Interface, where: [name: ^interface_name, major_version: ^major_version]

    case Repo.aggregate(query, :count, prefix: realm) do
      1 -> :ok
      0 -> {:error, :interface_not_found}
    end
  end
end
