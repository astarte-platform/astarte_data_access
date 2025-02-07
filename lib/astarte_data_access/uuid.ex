defmodule Astarte.DataAccess.UUID do
  @moduledoc """
  Ecto type for UUIDs, just like Ecto.UUID.
  The difference is that its internal representation, and thus its result after `load/1`,
  is `Ecto.UUID.raw`.
  """
  use Ecto.Type

  @type t :: Ecto.UUID.raw()
  @type encoded :: Ecto.UUID.t()

  @doc false
  def type, do: :uuid

  @spec load(t() | any()) :: {:ok, t()} | :error
  def load(<<_::128>> = uuid), do: {:ok, uuid}
  def load(other), do: Ecto.UUID.load(other)

  @spec dump(t() | encoded() | any()) :: {:ok, t()} | :error
  def dump(<<_::128>> = uuid), do: {:ok, uuid}
  def dump(other), do: Ecto.UUID.dump(other)

  # our internal representation is the same as the database representation
  @spec cast(t() | encoded() | any()) :: {:ok, t()} | :error
  def cast(uuid), do: dump(uuid)

  # callback invoked by autogenerate fields
  @doc false
  def autogenerate, do: Ecto.UUID.bingenerate()
end
