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

defmodule Astarte.DataAccess.Realms.Device do
  use Ecto.Schema
  import Ecto.Changeset

  alias Astarte.Core.Device

  @device_fields [
    :encoded_device_id,
    :aliases,
    :attributes,
    :cert_aki,
    :cert_serial,
    :connected,
    :credentials_secret,
    # :exchanged_bytes_by_interface,
    # :exchanged_msgs_by_interface,
    :first_credentials_request,
    :first_registration,
    :groups,
    :inhibit_credentials_request,
    :introspection,
    :introspection_minor,
    :last_connection,
    # :last_credentials_request_ip,
    :last_disconnection,
    # :last_seen_ip,
    # :old_introspection,
    :pending_empty_cache,
    :protocol_revision,
    :total_received_bytes,
    :total_received_msgs
  ]

  @primary_key {:device_id, :binary_id, autogenerate: false}
  schema "devices" do
    field :encoded_device_id, :binary, virtual: true

    field :aliases, Exandra.Map, key: :string, value: :string
    field :attributes, Exandra.Map, key: :string, value: :string
    field :cert_aki, :string
    field :cert_serial, :string
    field :connected, :boolean
    field :credentials_secret, :string
    # exchanged_bytes_by_interface map<frozen<tuple<ascii, int>>, bigint>,
    # exchanged_msgs_by_interface map<frozen<tuple<ascii, int>>, bigint>,
    field :first_credentials_request, :utc_datetime_usec
    field :first_registration, :utc_datetime_usec
    field :groups, Exandra.Map, key: :string, value: Ecto.UUID
    field :inhibit_credentials_request, :boolean
    field :introspection, Exandra.Map, key: :string, value: :integer
    field :introspection_minor, Exandra.Map, key: :string, value: :integer
    field :last_connection, :utc_datetime_usec
    # field :last_credentials_request_ip, inet
    field :last_disconnection, :utc_datetime_usec
    # field :last_seen_ip, inet
    # old_introspection map<frozen<tuple<ascii, int>>, int>,
    field :pending_empty_cache, :boolean
    field :protocol_revision, :integer
    field :total_received_bytes, :integer
    field :total_received_msgs, :integer
  end

  def changeset(device, attrs, _opts \\ []) do
    device
    |> cast(attrs, @device_fields)
    |> validate_device_ids()
  end

  defp validate_device_ids(changeset) do
    device_id = fetch_field!(changeset, :device_id)
    encoded_device_id = fetch_field!(changeset, :encoded_device_id)

    case {device_id, encoded_device_id} do
      {nil, nil} ->
        add_error(changeset, :device_id, "either device_id or encoded_device_id must be set")

      {device_id, nil} ->
        put_encoded_id(changeset, device_id)

      {nil, encoded_device_id} ->
        validate_decoded_id(changeset, encoded_device_id)

      {device_id, encoded_device_id} ->
        validate_encoded_id(changeset, device_id, encoded_device_id)
    end
  end

  defp validate_decoded_id(changeset, encoded_id) do
    {result, value} = Device.decode_device_id(encoded_id)

    case result do
      :ok -> put_change(changeset, :device_id, value)
      :error -> add_error(changeset, :encoded_device_id, "must be a valid encoded device id")
    end
  end

  defp put_encoded_id(changeset, device_id) do
    encoded_device_id = Device.encode_device_id(device_id)

    put_change(changeset, :encoded_device_id, encoded_device_id)
  end
  
  defp validate_encoded_id(changeset, device_id, encoded_id) do
    case Device.decode_device_id(encoded_id) do
      {:ok, ^device_id} ->
        changeset

      {:ok, other_id} ->
        add_error(
          changeset,
          :encoded_id,
          "is not the encoded form of %{given_device_id}, but of %{obtained_device_id}",
          given_device_id: device_id,
          obtained_device_id: other_id
        )

      {:error, _reason} ->
        add_error(changeset, :encoded_device_id, "must be a valid encoded device id")
    end
  end
end
