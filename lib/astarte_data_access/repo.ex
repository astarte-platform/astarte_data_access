defmodule Astarte.DataAccess.Repo do
  use Ecto.Repo, otp_app: :astarte_data_access, adapter: Exandra
  alias Astarte.DataAccess.Config

  @impl Ecto.Repo
  def init(_context, config) do
    config =
      Config.xandra_options!()
      |> Keyword.merge(config)

    {:ok, config}
  end

  def fetch(queryable, id, opts \\ []) do
    {error, opts} = Keyword.pop_first(opts, :error, :not_found)

    case get(queryable, id, opts) do
      nil -> {:error, error}
      item -> {:ok, item}
    end
  end

  def fetch_by(queryable, clauses, opts \\ []) do
    {error, opts} = Keyword.pop_first(opts, :error, :not_found)

    case get_by(queryable, clauses, opts) do
      nil -> {:error, error}
      item -> {:ok, item}
    end
  end

  def fetch_one(queryable, opts \\ []) do
    {error, opts} = Keyword.pop_first(opts, :error, :not_found)

    case one(queryable, opts) do
      nil -> {:error, error}
      item -> {:ok, item}
    end
  end

  @impl Ecto.Repo
  def default_options(_operation) do
    [uuid_format: :binary]
  end
end
