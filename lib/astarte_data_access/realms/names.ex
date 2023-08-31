defmodule AstarteDataAccess.Realms.Names do
  use Ecto.Schema

  @primary_key false
  schema "names" do
    field :object_name, :string, primary_key: true
    field :object_type, :integer, primary_key: true
    field :object_uuid, :binary_id
  end
end
