defmodule Mint.Core.Transport.SSLTest do
  use ExUnit.Case, async: true

  alias Mint.Core.Transport.SSL

  setup_all do
    {:module, :ssl} = Code.ensure_loaded(:ssl)
    :ok
  end

  describe "default ciphers" do
    setup do
      versions = SSL.ssl_versions()
      default_ciphers = SSL.get_ciphers_for_versions(versions)
      {:ok, %{default_ciphers: default_ciphers}}
    end

    test "no RSA key exchange", %{default_ciphers: default_ciphers} do
      # E.g. TLS_RSA_WITH_AES_256_GCM_SHA384 (old and new OTP variants)
      refute {:rsa, :aes_256_gcm, :aead, :sha384} in default_ciphers
      refute {:rsa, :aes_256_gcm, :null, :sha384} in default_ciphers
    end

    test "no AES CBC", %{default_ciphers: default_ciphers} do
      # E.g. TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
      refute {:ecdhe_rsa, :aes_256_cbc, :sha} in default_ciphers
    end

    test "no 3DES", %{default_ciphers: default_ciphers} do
      # E.g. TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
      refute {:ecdhe_rsa, :"3des_ede_cbc", :sha} in default_ciphers
    end
  end

  # Based on https://bugs.erlang.org/browse/ERL-542
  @wildcard_san Path.expand("../../../support/mint/wildcard_san.pem", __DIR__)

  describe "wildcard in SAN" do
    setup [:wildcard_san_cert]

    test "custom match fun for wildcard in SAN", %{cert: cert} do
      assert {:valid, _} = SSL.verify_fun(cert, :valid_peer, dns_id: ~c"outlook.office365.com")

      assert {:valid, _} = SSL.verify_fun(cert, :valid_peer, dns_id: ~c"Outlook.office365.COM")

      assert {:valid, _} =
               SSL.verify_fun(
                 cert,
                 :valid_peer,
                 dns_id: ~c"test.outlook.office365.com"
               )

      assert {:valid, _} =
               SSL.verify_fun(
                 cert,
                 :valid_peer,
                 uri_id: ~c"https://outlook.office365.com"
               )

      assert {:fail, {:bad_cert, :hostname_check_failed}} =
               SSL.verify_fun(cert, :valid_peer, dns_id: ~c"live.com")

      assert {:fail, {:bad_cert, :hostname_check_failed}} =
               SSL.verify_fun(cert, :valid_peer, dns_id: ~c"out.look.office365.com")
    end
  end

  # These certificates and the test cases that use them were taken from
  # the `public_key` library test suite in Erlang/OTP 20.3
  @cn_cert Path.expand("../../../support/mint/pkix_verify_hostname_cn.pem", __DIR__)
  @subj_alt_name_cert Path.expand(
                        "../../../support/mint/pkix_verify_hostname_subjAltName.pem",
                        __DIR__
                      )
  @subj_alt_name_ip_cert Path.expand(
                           "../../../support/mint/pkix_verify_hostname_subjAltName_IP.pem",
                           __DIR__
                         )

  describe "verify_hostname (CN)" do
    setup [:cn_cert]

    test "OTP public_key test cases", %{cert: cert} do
      # Check that 1) only CNs are checked,
      #            2) an empty label does not match a wildcard and
      #            3) a wildcard does not match more than one label
      refute :mint_shims.pkix_verify_hostname(
               cert,
               dns_id: ~c"erlang.org",
               dns_id: ~c"foo.EXAMPLE.com",
               dns_id: ~c"b.a.foo.EXAMPLE.com"
             )

      # Check that a hostname is extracted from a https-uri and used for checking:
      assert :mint_shims.pkix_verify_hostname(cert, uri_id: ~c"HTTPS://EXAMPLE.com")

      # Check wildcard matching one label:
      assert :mint_shims.pkix_verify_hostname(cert, dns_id: ~c"a.foo.EXAMPLE.com")

      # Check wildcard with surrounding chars matches one label:
      assert :mint_shims.pkix_verify_hostname(cert, dns_id: ~c"accb.bar.EXAMPLE.com")

      # Check that a wildcard with surrounding chars matches an empty string:
      assert :mint_shims.pkix_verify_hostname(cert, uri_id: ~c"https://ab.bar.EXAMPLE.com")
    end
  end

  describe "verify_hostname (subj_alt_name)" do
    setup [:subj_alt_name_cert]

    test "OTP public_key test cases", %{cert: cert} do
      # Check that neither a uri nor dns hostname matches a CN if subjAltName is present:
      refute :mint_shims.pkix_verify_hostname(
               cert,
               uri_id: ~c"https://example.com",
               dns_id: ~c"example.com"
             )

      # Check that a uri_id matches a URI subjAltName:
      assert :mint_shims.pkix_verify_hostname(cert, uri_id: ~c"https://wws.example.org")

      # Check that a dns_id does not match a URI subjAltName:
      refute :mint_shims.pkix_verify_hostname(
               cert,
               dns_id: ~c"www.example.org",
               dns_id: ~c"wws.example.org"
             )

      # Check that a dns_id matches a DNS subjAltName:
      assert :mint_shims.pkix_verify_hostname(cert, dns_id: ~c"kb.example.org")
    end
  end

  describe "verify_hostname (subj_alt_name_ip)" do
    setup [:subj_alt_name_ip_cert]

    test "OTP public_key test cases", %{cert: cert} do
      refute :mint_shims.pkix_verify_hostname(cert, uri_id: ~c"https://1.2.3.4")
      assert :mint_shims.pkix_verify_hostname(cert, uri_id: ~c"https://10.11.12.13")
      assert :mint_shims.pkix_verify_hostname(cert, dns_id: ~c"1.2.3.4")
      assert :mint_shims.pkix_verify_hostname(cert, dns_id: "1.2.3.4")
      refute :mint_shims.pkix_verify_hostname(cert, dns_id: ~c"10.67.16.75")
      assert :mint_shims.pkix_verify_hostname(cert, ip: ~c"aBcD:ef:0::0:1")
      assert :mint_shims.pkix_verify_hostname(cert, ip: {0xABCD, 0xEF, 0, 0, 0, 0, 0, 1})
      assert :mint_shims.pkix_verify_hostname(cert, ip: ~c"10.67.16.75")
      assert :mint_shims.pkix_verify_hostname(cert, ip: "10.67.16.75")
      assert :mint_shims.pkix_verify_hostname(cert, ip: {10, 67, 16, 75})
      refute :mint_shims.pkix_verify_hostname(cert, ip: {1, 2, 3, 4})
      refute :mint_shims.pkix_verify_hostname(cert, ip: {10, 11, 12, 13})
    end

    test "custom match fun for IP addresses as hostname", %{cert: cert} do
      assert {:valid, _} = SSL.verify_fun(cert, :valid_peer, dns_id: ~c"10.67.16.75")
    end
  end

  # Certificate chain rooted in an expired root CA, and CA store containing
  # expired and alternate root CAs
  @chain Path.expand("../../../support/mint/chain.pem", __DIR__)
  @ca_store Path.expand("../../../support/mint/ca_store.pem", __DIR__)

  describe "partial_chain/2" do
    setup [:chain_with_expired_root]

    test "ignore expired CA cert(s)", %{chain: chain, ca_store: ca_store} do
      [_, cross_signed | _] = chain
      assert {:trusted_ca, ^cross_signed} = SSL.partial_chain(ca_store, chain)
    end
  end

  describe "connect/3" do
    test "can connect to IPv6 addresses" do
      ssl_opts = [
        :inet6,
        mode: :binary,
        packet: :raw,
        active: false,
        reuseaddr: true,
        nodelay: true,
        certfile: Path.expand("../../../support/mint/certificate.pem", __DIR__),
        keyfile: Path.expand("../../../support/mint/key.pem", __DIR__)
      ]

      {:ok, listen_socket} = :ssl.listen(0, ssl_opts)
      {:ok, {_address, port}} = :ssl.sockname(listen_socket)

      task =
        Task.async(fn ->
          {:ok, socket} = :ssl.transport_accept(listen_socket)

          if function_exported?(:ssl, :handshake, 1) do
            {:ok, _} = apply(:ssl, :handshake, [socket])
          else
            :ok = apply(:ssl, :ssl_accept, [socket])
          end

          {:ok, socket}
        end)

      assert {:ok, _socket} =
               SSL.connect({0, 0, 0, 0, 0, 0, 0, 1}, port,
                 active: false,
                 inet6: true,
                 hostname: "::1",
                 timeout: 1000,
                 verify: :verify_none
               )

      assert {:ok, _server_socket} = Task.await(task)
    end

    test "can fall back to IPv4 if IPv6 fails" do
      ssl_opts = [
        mode: :binary,
        packet: :raw,
        active: false,
        reuseaddr: true,
        nodelay: true,
        certfile: Path.expand("../../../support/mint/certificate.pem", __DIR__),
        keyfile: Path.expand("../../../support/mint/key.pem", __DIR__)
      ]

      {:ok, listen_socket} = :ssl.listen(0, ssl_opts)
      {:ok, {_address, port}} = :ssl.sockname(listen_socket)

      task =
        Task.async(fn ->
          {:ok, socket} = :ssl.transport_accept(listen_socket)

          if function_exported?(:ssl, :handshake, 1) do
            {:ok, _} = apply(:ssl, :handshake, [socket])
          else
            :ok = apply(:ssl, :ssl_accept, [socket])
          end

          {:ok, socket}
        end)

      assert {:ok, _socket} =
               SSL.connect("localhost", port,
                 active: false,
                 inet6: true,
                 timeout: 1000,
                 verify: :verify_none
               )

      assert {:ok, _server_socket} = Task.await(task)
    end

    test "does not fall back to IPv4 if IPv4 is disabled" do
      ssl_opts = [
        :inet,
        mode: :binary,
        packet: :raw,
        active: false,
        reuseaddr: true,
        nodelay: true,
        certfile: Path.expand("../../../support/mint/certificate.pem", __DIR__),
        keyfile: Path.expand("../../../support/mint/key.pem", __DIR__)
      ]

      {:ok, listen_socket} = :ssl.listen(0, ssl_opts)
      {:ok, {_address, port}} = :ssl.sockname(listen_socket)

      Task.async(fn ->
        {:ok, _socket} = :ssl.transport_accept(listen_socket)
      end)

      assert {:error, %Mint.TransportError{reason: :econnrefused}} =
               SSL.connect("localhost", port,
                 active: false,
                 inet6: true,
                 inet4: false,
                 timeout: 1000,
                 verify: :verify_none
               )
    end
  end

  describe "controlling_process/2" do
    @describetag :capture_log

    setup do
      parent = self()
      ref = make_ref()

      ssl_opts = [
        mode: :binary,
        packet: :raw,
        active: false,
        reuseaddr: true,
        nodelay: true,
        certfile: Path.expand("../../../support/mint/certificate.pem", __DIR__),
        keyfile: Path.expand("../../../support/mint/key.pem", __DIR__)
      ]

      spawn_link(fn ->
        {:ok, listen_socket} = :ssl.listen(0, ssl_opts)
        {:ok, {_address, port}} = :ssl.sockname(listen_socket)
        send(parent, {ref, port})

        {:ok, socket} = :ssl.transport_accept(listen_socket)

        if function_exported?(:ssl, :handshake, 1) do
          {:ok, _} = apply(:ssl, :handshake, [socket])
        else
          :ok = apply(:ssl, :ssl_accept, [socket])
        end

        send(parent, {ref, socket})

        # Keep the server alive forever.
        :ok = Process.sleep(:infinity)
      end)

      assert_receive {^ref, port} when is_integer(port), 500

      {:ok, socket} = SSL.connect("localhost", port, verify: :verify_none)
      assert_receive {^ref, server_socket}, 200

      {:ok, server_port: port, socket: socket, server_socket: server_socket}
    end

    test "changing the controlling process of a active: :once socket",
         %{socket: socket, server_socket: server_socket} do
      parent = self()
      ref = make_ref()

      # Send two SSL messages (that get translated to Erlang messages right
      # away because of "nodelay: true"), but wait after each one so that
      # it actually arrives and we can set the socket back to active: :once.
      :ok = SSL.setopts(socket, active: :once)
      :ok = :ssl.send(server_socket, "some data 1")
      Process.sleep(100)

      :ok = SSL.setopts(socket, active: :once)
      :ok = :ssl.send(server_socket, "some data 2")

      wait_until_passes(500, fn ->
        {:messages, messages} = Process.info(self(), :messages)
        assert {:ssl, socket, "some data 1"} in messages
        assert {:ssl, socket, "some data 2"} in messages
      end)

      other_process = spawn_link(fn -> process_mirror(parent, ref) end)

      assert :ok = SSL.controlling_process(socket, other_process)

      assert_receive {^ref, {:ssl, ^socket, "some data 1"}}
      assert_receive {^ref, {:ssl, ^socket, "some data 2"}}

      refute_received _message
    end

    test "changing the controlling process of a passive socket",
         %{socket: socket, server_socket: server_socket} do
      parent = self()
      ref = make_ref()

      :ok = :ssl.send(server_socket, "some data")

      other_process =
        spawn_link(fn ->
          assert_receive message, 500
          send(parent, {ref, message})
        end)

      assert :ok = SSL.controlling_process(socket, other_process)
      assert {:ok, [active: false]} = SSL.getopts(socket, [:active])
      :ok = SSL.setopts(socket, active: :once)

      assert_receive {^ref, {:ssl, ^socket, "some data"}}, 500

      refute_received _message
    end

    test "changing the controlling process of a closed socket",
         %{socket: socket} do
      other_process = spawn_link(fn -> :ok = Process.sleep(:infinity) end)

      :ok = SSL.close(socket)

      assert {:error, _error} = SSL.controlling_process(socket, other_process)
    end
  end

  describe "upgrade/4" do
    test "raises an error if the scheme is :https" do
      assert_raise RuntimeError, "nested SSL sessions are not supported", fn ->
        SSL.upgrade(_fake_socket = nil, :https, ~c"localhost", _port = 0, _timeout = 5000)
      end
    end
  end

  defp cn_cert(_context) do
    [cert: load_cert(@cn_cert)]
  end

  defp subj_alt_name_cert(_context) do
    [cert: load_cert(@subj_alt_name_cert)]
  end

  defp subj_alt_name_ip_cert(_context) do
    [cert: load_cert(@subj_alt_name_ip_cert)]
  end

  defp wildcard_san_cert(_context) do
    [cert: load_cert(@wildcard_san)]
  end

  defp chain_with_expired_root(_context) do
    [
      chain: load_all_certs(@chain),
      ca_store: Enum.map(load_all_certs(@ca_store), &:public_key.pkix_decode_cert(&1, :plain))
    ]
  end

  defp load_cert(path) do
    [{_, binary, _} | _] = path |> File.read!() |> :public_key.pem_decode()
    :public_key.pkix_decode_cert(binary, :otp)
  end

  defp load_all_certs(path) do
    path
    |> File.read!()
    |> :public_key.pem_decode()
    |> Enum.map(&elem(&1, 1))
  end

  defp process_mirror(parent, ref) do
    receive do
      message ->
        send(parent, {ref, message})
        process_mirror(parent, ref)
    end
  end

  defp wait_until_passes(time_left, fun) when time_left <= 0 do
    fun.()
  end

  defp wait_until_passes(time_left, fun) do
    fun.()
  rescue
    _exception ->
      Process.sleep(10)
      wait_until_passes(time_left - 10, fun)
  end
end
