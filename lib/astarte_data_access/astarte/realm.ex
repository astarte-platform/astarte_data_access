defmodule AstarteDataAccess.Astarte.Realm do
  use Ecto.Schema

  @primary_key {:realm_name, :string, autogenerate: false}
  schema "realms" do
  end
end
