defmodule AstarteDataAccess.Realms.Device do
  use Ecto.Schema

  @primary_key {:device_id, :binary_id, autogenerate: false}
  schema "devices" do
    field :aliases, Exandra.Map, key: :ascii, value: :string
    field :introspection, Exandra.Map, key: :ascii, value: :integer
    field :protocol_revision, :integer
    field :first_registration, :utc_datetime_usec
    field :credentials_secret, :string
    field :inhibit_credentials_request, :boolean
    field :cert_serial, :string
    field :cert_aki, :string
    field :first_credentials_request, :utc_datetime_usec
    field :last_connection, :utc_datetime_usec
    field :last_disconnection, :utc_datetime_usec
    field :connected, :boolean
    field :pending_empty_cache, :boolean
    field :total_received_msgs, :integer
    field :total_received_bytes, :integer
    field :last_credentials_request_ip, :string
    field :last_seen_ip, :string
  end
end
