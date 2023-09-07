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

defmodule Astarte.DataAccess.Data do
  require Logger
  alias Astarte.DataAccess.Repo
  alias Astarte.DataAccess.Realms.IndividualProperty
  alias Astarte.DataAccess.XandraUtils
  alias Astarte.Core.CQLUtils
  alias Astarte.Core.Device
  alias Astarte.Core.InterfaceDescriptor
  alias Astarte.Core.Mapping
  import Ecto.Query

  @individual_properties_table "individual_properties"

  @spec fetch_property(
          String.t(),
          Device.device_id(),
          %InterfaceDescriptor{},
          %Mapping{},
          String.t()
        ) :: {:ok, any} | {:error, atom}
  def fetch_property(
        realm,
        device_id,
        %InterfaceDescriptor{storage_type: :multi_interface_individual_properties_dbtable} =
          interface_descriptor,
        mapping,
        path
      )
      when is_binary(device_id) and is_binary(path) do
    # String.to_existing_atom doesn't work as... the atom doesn't exist
    # Maybe CQLUtils could expose a `type_to_db_column_atom`?
    column =
      mapping.value_type
      |> CQLUtils.type_to_db_column_name()
      |> String.to_atom()

    # FIXME: cassandra complains it doesn't know a "castAsUuid" function,
    # but the ids are correctly casted as UUIDs in the query, which doesn't happen setting type to "string".
    # Perhaps an exandra issue?

    # TODO: add typing to fetch/6 and use that once this is sorted out
    query =
      from interface_descriptor.storage,
        prefix: ^realm,
        where: [
          device_id: type(^device_id, Ecto.UUID),
          interface_id: type(^interface_descriptor.interface_id, Ecto.UUID),
          endpoint_id: type(^mapping.endpoint_id, Ecto.UUID),
          path: type(^path, :string)
        ],
        select: [^column]

    with {:ok, %{^column => value}} <-
           Repo.fetch_one(query, consistency: :quorum, error: :property_not_set) do
      if value == nil do
        {:error, :undefined_property}
      else
        {:ok, value}
      end
    end
  end

  @spec path_exists?(
          String.t(),
          Device.device_id(),
          %InterfaceDescriptor{},
          %Mapping{},
          String.t()
        ) :: {:ok, boolean} | {:error, atom}
  def path_exists?(
        realm,
        device_id,
        interface_descriptor,
        mapping,
        path
      )
      when is_binary(device_id) and is_binary(path) do
    fetch(realm, device_id, interface_descriptor, mapping, path)
    |> Repo.aggregate(:count, consistency: :quorum)
    |> case do
      0 -> {:ok, false}
      1 -> {:ok, true}
    end
  end

  @spec fetch_last_path_update(
          String.t(),
          Device.device_id(),
          %InterfaceDescriptor{},
          %Mapping{},
          String.t()
        ) ::
          {:ok, %{value_timestamp: DateTime.t(), reception_timestamp: DateTime.t()}}
          | {:error, atom}
  def fetch_last_path_update(
        realm,
        device_id,
        interface_descriptor,
        mapping,
        path
      )
      when is_binary(device_id) and is_binary(path) do
    query =
      fetch(realm, device_id, interface_descriptor, mapping, path)
      |> select([:datetime_value, :reception_timestamp, :reception_timestamp_submillis])

    with {:ok, last_update} <- Repo.fetch_one(query, error: :path_not_set) do
      value_timestamp = last_update.datetime_value |> DateTime.truncate(:millisecond)
      reception_timestamp = IndividualProperty.reception(last_update)

      {:ok, %{value_timestamp: value_timestamp, reception_timestamp: reception_timestamp}}
    end
  end

  defp fetch(source \\ IndividualProperty, realm, device_id, interface_descriptor, mapping, path) do
    from source,
      prefix: ^realm,
      where: [
        device_id: ^device_id,
        interface_id: ^interface_descriptor.interface_id,
        endpoint_id: ^mapping.endpoint_id,
        path: ^path
      ]
  end
end
