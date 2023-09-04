defmodule Astarte.DataAccess.Repo do
  use Ecto.Repo, otp_app: :astarte_data_access, adapter: Exandra
  alias Astarte.DataAccess.Config

  def init(_context, config) do
    config =
      Config.xandra_options!()
      |> Keyword.merge(config)

    {:ok, config}
  end
end
