defmodule Mint.TestCertificates do
  @moduledoc false

  # Generates a fresh CA and server certificate chain at runtime, with a
  # server certificate valid for "localhost" (SAN), so tests can exercise
  # verify_peer against local servers without committed fixtures that expire.
  def pkix_test_chain do
    san_extension = {:Extension, {2, 5, 29, 17}, false, [dNSName: ~c"localhost"]}
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
