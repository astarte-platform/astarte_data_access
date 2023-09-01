defmodule AstarteDataAccess.Realms.KvStore do
  use Ecto.Schema

  @primary_key false
  schema "kv_store" do
    field(:group, :string, primary_key: true)
    field(:key, :string, primary_key: true)
    field(:value, :binary)
  end
end
