defmodule Mint.TestCertificates do
  @moduledoc false

  # Generates a fresh CA and server certificate chain at runtime, with a
  # server certificate valid for the :hostname option ("localhost" by default,
  # as SAN), so tests can exercise verify_peer against local servers without
  # committed fixtures that expire.
  def pkix_test_chain(opts \\ []) do
    hostname = Keyword.get(opts, :hostname, "localhost")
    san_extension = {:Extension, {2, 5, 29, 17}, false, [dNSName: String.to_charlist(hostname)]}
    cert_opts = [digest: :sha256, key: {:rsa, 2048, 17}]

    :public_key.pkix_test_data(%{
      server_chain: %{
        root: cert_opts,
        intermediates: [],
        peer: cert_opts ++ [extensions: [san_extension]]
      },
      client_chain: %{
        root: cert_opts,
        intermediates: [],
        peer: cert_opts
      }
    })
  end
end
