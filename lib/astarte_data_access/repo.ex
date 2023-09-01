defmodule Astarte.DataAccess.Repo do
  use Ecto.Repo, otp_app: :astarte_data_access, adapter: Exandra
end
