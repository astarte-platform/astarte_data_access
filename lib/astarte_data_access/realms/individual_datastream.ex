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

defmodule Astarte.DataAccess.Realms.IndividualDatastream do
  use Ecto.Schema

  alias Ecto.Changeset
  alias Astarte.DataAccess.Realms.IndividualProperty

  @type t :: %__MODULE__{}
  @type data :: t() | IndividualProperty.t()

  @datastream_fields [
    :reception,
    :device_id,
    :interface_id,
    :endpoint_id,
    :path,
    :value_timestamp,
    :reception_timestamp,
    :reception_timestamp_submillis,
    :binaryblob_value,
    :binaryblobarray_value,
    :boolean_value,
    :booleanarray_value,
    :datetime_value,
    :datetimearray_value,
    :double_value,
    :doublearray_value,
    :integer_value,
    :integerarray_value,
    :longinteger_value,
    :longintegerarray_value,
    :string_value,
    :stringarray_value
  ]

  @primary_key false
  schema "individual_datastreams" do
    field :reception, :utc_datetime_usec, virtual: true
    field :device_id, Ecto.UUID, primary_key: true
    field :interface_id, Ecto.UUID, primary_key: true
    field :endpoint_id, Ecto.UUID, primary_key: true
    field :path, :string, primary_key: true
    field :value_timestamp, :utc_datetime_usec, primary_key: true
    field :reception_timestamp, :utc_datetime_usec, primary_key: true
    field :reception_timestamp_submillis, :integer, primary_key: true
    field :binaryblob_value, :binary
    field :binaryblobarray_value, {:array, :binary}
    field :boolean_value, :boolean
    field :booleanarray_value, {:array, :boolean}
    field :datetime_value, :utc_datetime_usec
    field :datetimearray_value, {:array, :utc_datetime_usec}
    field :double_value, :float
    field :doublearray_value, {:array, :float}
    field :integer_value, :integer
    field :integerarray_value, {:array, :integer}
    field :longinteger_value, :integer
    field :longintegerarray_value, {:array, :integer}
    field :string_value, :string
    field :stringarray_value, {:array, :string}
  end

  def changeset(datastream, attrs, _opts \\ []) do
    datastream
    |> Changeset.cast(attrs, @datastream_fields)
    |> load_receptions()
  end

  @spec load_receptions(Changeset.t(data())) :: Changeset.t(data())
  def load_receptions(changeset) do
    reception = Changeset.fetch_field!(changeset, :reception)
    timestamp = Changeset.fetch_field!(changeset, :reception_timestamp)
    submillis = Changeset.fetch_field!(changeset, :reception_timestamp_submillis)

    case {reception, timestamp, submillis} do
      {reception, nil, nil} -> put_reception_timestamps(changeset, reception)
      {nil, timestamp, submillis} -> put_reception(changeset, timestamp, submillis)
      _ -> changeset
    end
  end

  defp put_reception_timestamps(changeset, nil), do: changeset

  defp put_reception_timestamps(changeset, reception) do
    reception_timestamp =
      reception
      |> DateTime.truncate(:millisecond)

    reception_timestamp_submillis =
      reception
      |> DateTime.to_unix(:nanosecond)
      |> div(100)
      |> rem(10_000)

    changeset
    |> Changeset.put_change(:reception_timestamp, reception_timestamp)
    |> Changeset.put_change(:reception_timestamp_submillis, reception_timestamp_submillis)
  end

  defp put_reception(changeset, timestamp, submillis) do
    changeset
    |> Changeset.put_change(:reception, calculate_reception(timestamp, submillis))
  end

  @spec reception(data()) :: data()
  def reception(data) do
    data.reception ||
      calculate_reception(data.reception_timestamp, data.reception_timestamp_submillis)
  end

  defp calculate_reception(nil = _reception_timestamp, _reception_timestamp_submillis), do: nil

  defp calculate_reception(reception_timestamp, reception_timestamp_submillis) do
    nanos =
      reception_timestamp_submillis
      |> Kernel.||(0)
      |> Kernel.*(100)

    reception_timestamp
    |> DateTime.add(nanos, :nanosecond)
  end
end
