defmodule AstarteDataAccess.Realms.Interface do
  use Ecto.Schema

  @primary_key false
  schema "interfaces" do
    field(:name, :string, primary_key: true)
    field(:major_version, :integer, primary_key: true)
    field(:minor_version, :integer)
    field(:interface_id, :binary_id)
    field(:storage_type, :integer)
    field(:storage, :string)
    field(:type, :integer)
    field(:ownership, :integer)
    field(:aggregation, :integer)
    field(:automaton_transitions, :binary)
    field(:automaton_accepting_states, :binary)
    field(:description, :string)
    field(:doc, :string)
  end
end
