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

defmodule Astarte.DataAccess.Device do
  require Logger
  alias Astarte.Core.Device
  alias Astarte.DataAccess.Repo
  import Ecto.Query

  @spec interface_version(String.t(), Device.device_id(), String.t()) ::
          {:ok, integer} | {:error, atom}
  def interface_version(realm, device_id, interface_name) do
    query =
      from d in "devices",
        where: d.device_id == ^device_id,
        select: d.introspection

    with {:ok, introspection} <-
           Repo.fetch_one(query, prefix: realm, error: :device_not_found),
         {:ok, major} <- retrieve_major(introspection, interface_name) do
      {:ok, major}
    end
  end

  defp retrieve_major(introspection, interface_name) do
    with :error <- Map.fetch(introspection, interface_name) do
      {:error, :interface_not_in_introspection}
    end
  end
end
