defmodule Totpex do
  @moduledoc """
  Generate a Time-Based One-Time Password used from 2 factor authentication.
  Official specification: https://tools.ietf.org/html/rfc6238
  """

  defp generate_hmac(secret, period) do
    # Clean unwanted character from the secret and decode it using Base32 "encoding"
    key = secret
          |> String.replace(" ", "")
          |> String.upcase
          |> Base.decode32!

    # Generate the moving mactor
    moving_factor = DateTime.utc_now
                    |> DateTime.to_unix
                    |> Integer.floor_div(period)
                    |> Integer.to_string(16)
                    |> String.pad_leading(16, "0")
                    |> String.upcase
                    |> Base.decode16!

    # Generate SHA-1
    :crypto.hmac(:sha, key, moving_factor)
  end

  defp hmac_dynamic_truncation(hmac) do
    # Get the offset from last  4-bits
    <<_::19-binary, _::4, offset::4>> = hmac

    # Get the 4-bytes starting from the offset
    <<_::size(offset)-binary, p::4-binary, _::binary>> = hmac

    # Return the last 31-bits
    <<_::1, truncation::31>> = p

    truncation
  end

  defp generate_hotp(truncated_hmac) do
    truncated_hmac
    |> rem(1000000)
    |> Integer.to_string
    |> String.pad_leading(6, "0")
  end

  @doc """
  Generate Time-Based One-Time Password.
  The default period used to calculate the moving factor is 30s
  """
  def generate_totp(secret, period \\ 30) do
    secret
    |> generate_hmac(period)
    |> hmac_dynamic_truncation
    |> generate_hotp
  end
end
