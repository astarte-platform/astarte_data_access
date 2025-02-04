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

defmodule Astarte.DataAccess.Realms.Endpoint do
  use TypedEctoSchema

  alias Astarte.Core.Interface.Type, as: InterfaceType
  alias Astarte.Core.Mapping.DatabaseRetentionPolicy
  alias Astarte.Core.Mapping.Reliability
  alias Astarte.Core.Mapping.Retention
  alias Astarte.Core.Mapping.ValueType

  @primary_key false
  typed_schema "endpoints" do
    field :interface_id, Astarte.DataAccess.UUID, primary_key: true
    field :endpoint_id, Astarte.DataAccess.UUID, primary_key: true
    field :allow_unset, :boolean
    field :database_retention_policy, DatabaseRetentionPolicy
    field :database_retention_ttl, :integer
    field :description, :string
    field :doc, :string
    field :endpoint, :string
    field :expiry, :integer
    field :explicit_timestamp, :boolean
    field :interface_major_version, :integer
    field :interface_minor_version, :integer
    field :interface_name, :string
    field :interface_type, InterfaceType
    field :reliability, Reliability
    field :retention, Retention
    field :value_type, ValueType
  end
end
