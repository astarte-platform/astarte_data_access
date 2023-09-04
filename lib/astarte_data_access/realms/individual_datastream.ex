defmodule Astarte.DataAccess.Realms.IndividualDatastream do
  use Ecto.Schema

  @primary_key false
  schema "individual_datastreams" do
    field :device_id, Ecto.UUID, primary_key: true
    field :interface_id, Ecto.UUID, primary_key: true
    field :endpoint_id, Ecto.UUID, primary_key: true
    field :path, :string, primary_key: true
    field :value_timestamp, :utc_datetime_usec, primary_key: true
    field :reception_timestamp, :utc_datetime_usec, primary_key: true
    field :reception_timestamp_submillis, :integer, primary_key: true
    field :reception, :utc_datetime, virtual: true
    field :double_value, :float
    field :integer_value, :integer
    field :boolean_value, :boolean
    field :longinteger_value, :integer
    field :string_value, :string
    field :binaryblob_value, :binary
    field :datetime_value, :utc_datetime_usec
    field :doublearray_value, {:array, :float}
    field :integerarray_value, {:array, :integer}
    field :booleanarray_value, {:array, :boolean}
    field :longintegerarray_value, {:array, :integer}
    field :stringarray_value, {:array, :string}
    field :binaryblobarray_value, {:array, :binary}
    field :datetimearray_value, {:array, :utc_datetime_usec}
  end
end
