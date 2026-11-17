defmodule Mint.CacertsGetTest do
  # :public_key.cacerts_load/1 replaces the CA store that
  # :public_key.cacerts_get/0 returns for the whole VM, so these tests can't
  # run concurrently with other tests.
  use ExUnit.Case, async: false

  alias Mint.{TransportError, HTTP, TestCertificates, TLSTestServer}

  if List.to_integer(:erlang.system_info(:otp_release)) < 25 do
    @moduletag :skip
  end

  setup do
    cacertfile =
      Path.join(
        System.tmp_dir!(),
        "mint_cacerts_get_test_#{System.unique_integer([:positive])}.pem"
      )

    on_exit(fn ->
      apply(:public_key, :cacerts_load, [])
      File.rm(cacertfile)
    end)

    %{cacertfile: cacertfile}
  end

  @tag :capture_log
  test "using :public_key.cacerts_get/0", %{cacertfile: cacertfile} do
    trusted = TestCertificates.pkix_test_chain()
    untrusted = TestCertificates.pkix_test_chain()

    pem_entries =
      for der <- trusted.client_config[:cacerts], do: {:Certificate, der, :not_encrypted}

    File.write!(cacertfile, :public_key.pem_encode(pem_entries))
    :ok = apply(:public_key, :cacerts_load, [cacertfile])

    cacerts = apply(:public_key, :cacerts_get, [])

    {:ok, untrusted_port} = TLSTestServer.start(untrusted.server_config)
    {:ok, trusted_port} = TLSTestServer.start(trusted.server_config)

    assert {:error, %TransportError{}} =
             HTTP.connect(
               :https,
               "localhost",
               untrusted_port,
               transport_opts: [
                 log_alert: false,
                 reuse_sessions: false,
                 cacerts: cacerts
               ]
             )

    assert {:ok, _conn} =
             HTTP.connect(
               :https,
               "localhost",
               trusted_port,
               transport_opts: [reuse_sessions: false, cacerts: cacerts]
             )
  end
end
