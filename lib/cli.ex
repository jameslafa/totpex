defmodule Totpex.CLI do
  def main(_args) do
    totp = get_secret()
           |> Totpex.generate_totp()

    IO.puts("Your One-Time Password is #{totp}")
  end

  defp get_secret() do
    secret = IO.gets("Please enter your secret key: ") |> String.trim

    cond do
      String.length(secret) > 0 ->
        secret
      true ->
        exit("Please provide only your secret key as argument. Ex: ./totpex qdhu123hsadca")
    end
  end
end
