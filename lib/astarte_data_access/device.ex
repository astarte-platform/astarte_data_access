#
# This file is part of Astarte.
#
# Copyright 2018 - 2024 SECO Mind Srl
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

defmodule Astarte.DataAccess.Device do
  require Logger
  alias Astarte.Core.Device, as: DeviceCore
  alias Astarte.DataAccess.Realms.Device
  alias Astarte.DataAccess.Repo
  alias Astarte.DataAccess.XandraUtils
  alias Ecto.UUID

  import Ecto.Query

  @spec interface_version(String.t(), DeviceCore.device_id(), String.t()) ::
          {:ok, integer} | {:error, atom}
  def interface_version(realm, device_id, interface_name) do
    with {:ok, device_id} <- cast_device_id(device_id),
         {:ok, device} <-
           introspection_query(realm, device_id)
           |> Repo.fetch_one(error: :device_not_found),
         {:ok, major} <- retrieve_major(device.introspection, interface_name) do
      {:ok, major}
    end
  end

  defp retrieve_major(introspection, interface_name) do
    case introspection do
      %{^interface_name => major} -> {:ok, major}
      _else -> {:error, :interface_not_in_introspection}
    end
  end

  defp introspection_query(realm, device_id) do
    keyspace = XandraUtils.realm_name_to_keyspace_name(realm)

    from Device,
      prefix: ^keyspace,
      where: [device_id: ^device_id],
      select: [:introspection]
  end

  defp cast_device_id(device_id) do
    case UUID.cast(device_id) do
      {:ok, device_id} -> {:ok, device_id}
      :error -> {:error, :invalid_device_id}
    end
  end
end
