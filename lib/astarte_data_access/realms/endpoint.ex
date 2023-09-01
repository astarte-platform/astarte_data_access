defmodule Astarte.DataAccess.Realms.Endpoint do
  use Ecto.Schema

  @primary_key false
  schema "endpoints" do
    field(:interface_id, :binary_id, primary_key: true)
    field(:endpoint_id, :binary_id, primary_key: true)
    field(:interface_name, :string)
    field(:interface_major_version, :integer)
    field(:interface_minor_version, :integer)
    field(:interface_type, :integer)
    field(:endpoint, :string)
    field(:value_type, :integer)
    field(:reliability, :integer)
    field(:retention, :integer)
    field(:database_retention_policy, :integer)
    field(:database_retention_ttl, :integer)
    field(:expiry, :integer)
    field(:allow_unset, :boolean)
    field(:explicit_timestamp, :boolean)
    field(:description, :string)
    field(:doc, :string)
  end
end
