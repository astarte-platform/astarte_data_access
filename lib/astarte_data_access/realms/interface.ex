#
# This file is part of Astarte.
#
# Copyright 2025 SECO Mind Srl
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

defmodule Astarte.DataAccess.Realms.Interface do
  use TypedEctoSchema

  alias Astarte.Core.Interface.Aggregation
  alias Astarte.Core.Interface.Ownership
  alias Astarte.Core.Interface.Type
  alias Astarte.Core.StorageType

  @primary_key false
  typed_schema "interfaces" do
    field :name, :string, primary_key: true
    field :major_version, :integer, primary_key: true
    field :aggregation, Aggregation
    field :automaton_accepting_states, :binary
    field :automaton_transitions, :binary
    field :description, :string
    field :doc, :string
    field :interface_id, Astarte.DataAccess.UUID
    field :minor_version, :integer
    field :ownership, Ownership
    field :storage, :string
    field :storage_type, StorageType
    field :type, Type
  end
end
