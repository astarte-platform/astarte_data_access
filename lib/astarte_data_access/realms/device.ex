defmodule AstarteDataAccess.Realms.Device do
  use Ecto.Schema
  import Ecto.Changeset

  alias Astarte.Core.Device

  @primary_key {:device_id, :binary_id, autogenerate: false}
  schema "devices" do
    field(:encoded_device_id, :binary, virtual: true)
    field(:aliases, Exandra.Map, key: :ascii, value: :string)
    field(:introspection, Exandra.Map, key: :ascii, value: :integer)
    field(:protocol_revision, :integer)
    field(:first_registration, :utc_datetime_usec)
    field(:credentials_secret, :string)
    field(:inhibit_credentials_request, :boolean)
    field(:cert_serial, :string)
    field(:cert_aki, :string)
    field(:first_credentials_request, :utc_datetime_usec)
    field(:last_connection, :utc_datetime_usec)
    field(:last_disconnection, :utc_datetime_usec)
    field(:connected, :boolean)
    field(:pending_empty_cache, :boolean)
    field(:total_received_msgs, :integer)
    field(:total_received_bytes, :integer)
    field(:last_credentials_request_ip, :string)
    field(:last_seen_ip, :string)
  end

  def changeset(device, attrs, _opts \\ []) do
    device
    |> cast(attrs, [
      :device_id,
      :encoded_device_id,
      :aliases,
      :introspection,
      :protocol_revision,
      :first_registration,
      :credentials_secret,
      :inhibit_credentials_request,
      :cert_serial,
      :cert_aki,
      :first_credentials_request,
      :last_connection,
      :last_disconnection,
      :connected,
      :pending_empty_cache,
      :total_received_msgs,
      :total_received_bytes,
      :last_credentials_request_ip,
      :last_seen_ip
    ])
    |> populate_and_validate_device_ids()
  end

  defp populate_and_validate_device_ids(changeset) do
    device_id = fetch_field!(changeset, :device_id)
    encoded_device_id = fetch_field!(changeset, :encoded_device_id)

    case {device_id, encoded_device_id} do
      {nil, nil} -> no_id_error(changeset)
      {id, nil} -> put_encoded_id(changeset, id)
      {nil, id} -> put_decoded_id(changeset, id)
      {d_id, e_id} -> validate_encoded_id(changeset, d_id, e_id)
    end
  end

  defp put_decoded_id(changeset, encoded_id) do
    changeset = validate_encoded_id(changeset, nil, encoded_id)

    case changeset do
      %{valid?: true} -> put_decoded_id!(changeset, encoded_id)
      _ -> changeset
    end
  end

  defp put_decoded_id!(changeset, encoded_id) do
    {:ok, id} = Device.decode_device_id(encoded_id)
    put_change(changeset, :device_id, id)
  end

  defp put_encoded_id(changeset, device_id) do
    encoded_device_id = Device.encode_device_id(device_id)

    changeset
    |> put_change(:encoded_device_id, encoded_device_id)
  end

  defp validate_encoded_id(changeset, nil, encoded_id) do
    if :ok == encoded_id |> Device.decode_device_id() |> elem(0) do
      changeset
    else
      add_error(changeset, :encoded_device_id, "must be a valid encoded device id")
    end
  end

  defp validate_encoded_id(changeset, device_id, encoded_id) do
    case Device.decode_device_id(encoded_id) do
      {:ok, ^device_id} ->
        changeset

      {:ok, other_id} ->
        add_error(
          changeset,
          :encoded_id,
          "is not the encoded form of %{given_device_id}. It corresponds to %{obtained_device_id}",
          given_device_id: device_id,
          obtained_device_id: other_id
        )

      {:error, _reason} ->
        add_error(changeset, :encoded_device_id, "must be a valid encoded device id")
    end
  end

  defp no_id_error(changeset) do
    changeset
    |> add_error(:device_id, "either device_id or encoded_device_id should be set")
  end
end
