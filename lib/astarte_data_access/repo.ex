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

defmodule Astarte.DataAccess.Repo do
  use Ecto.Repo, otp_app: :astarte_data_access, adapter: Exandra
  alias Astarte.DataAccess.Config

  @impl Ecto.Repo
  def init(_context, config) do
    config =
      Config.xandra_options!()
      |> Keyword.merge(config)

    {:ok, config}
  end

  def fetch(queryable, id, opts \\ []) do
    {error, opts} = Keyword.pop_first(opts, :error, :not_found)

    case get(queryable, id, opts) do
      nil -> {:error, error}
      item -> {:ok, item}
    end
  end

  def fetch_by(queryable, clauses, opts \\ []) do
    {error, opts} = Keyword.pop_first(opts, :error, :not_found)

    case get_by(queryable, clauses, opts) do
      nil -> {:error, error}
      item -> {:ok, item}
    end
  end

  def fetch_one(queryable, opts \\ []) do
    {error, opts} = Keyword.pop_first(opts, :error, :not_found)

    case one(queryable, opts) do
      nil -> {:error, error}
      item -> {:ok, item}
    end
  end
end
