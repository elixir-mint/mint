defmodule Mint.Core.Transport.SSL do
  @moduledoc false

  require Logger
  require Record

  @behaviour Mint.Core.Transport

  # From RFC7540 appendix A
  @blacklisted_ciphers [
    {:null, :null, :null},
    {:rsa, :null, :md5},
    {:rsa, :null, :sha},
    {:rsa_export, :rc4_40, :md5},
    {:rsa, :rc4_128, :md5},
    {:rsa, :rc4_128, :sha},
    {:rsa_export, :rc2_cbc_40, :md5},
    {:rsa, :idea_cbc, :sha},
    {:rsa_export, :des40_cbc, :sha},
    {:rsa, :des_cbc, :sha},
    {:rsa, :"3des_ede_cbc", :sha},
    {:dh_dss_export, :des40_cbc, :sha},
    {:dh_dss, :des_cbc, :sha},
    {:dh_dss, :"3des_ede_cbc", :sha},
    {:dh_rsa_export, :des40_cbc, :sha},
    {:dh_rsa, :des_cbc, :sha},
    {:dh_rsa, :"3des_ede_cbc", :sha},
    {:dhe_dss_export, :des40_cbc, :sha},
    {:dhe_dss, :des_cbc, :sha},
    {:dhe_dss, :"3des_ede_cbc", :sha},
    {:dhe_rsa_export, :des40_cbc, :sha},
    {:dhe_rsa, :des_cbc, :sha},
    {:dhe_rsa, :"3des_ede_cbc", :sha},
    {:dh_anon_export, :rc4_40, :md5},
    {:dh_anon, :rc4_128, :md5},
    {:dh_anon_export, :des40_cbc, :sha},
    {:dh_anon, :des_cbc, :sha},
    {:dh_anon, :"3des_ede_cbc", :sha},
    {:krb5, :des_cbc, :sha},
    {:krb5, :"3des_ede_cbc", :sha},
    {:krb5, :rc4_128, :sha},
    {:krb5, :idea_cbc, :sha},
    {:krb5, :des_cbc, :md5},
    {:krb5, :"3des_ede_cbc", :md5},
    {:krb5, :rc4_128, :md5},
    {:krb5, :idea_cbc, :md5},
    {:krb5_export, :des_cbc_40, :sha},
    {:krb5_export, :rc2_cbc_40, :sha},
    {:krb5_export, :rc4_40, :sha},
    {:krb5_export, :des_cbc_40, :md5},
    {:krb5_export, :rc2_cbc_40, :md5},
    {:krb5_export, :rc4_40, :md5},
    {:psk, :null, :sha},
    {:dhe_psk, :null, :sha},
    {:rsa_psk, :null, :sha},
    {:rsa, :aes_128_cbc, :sha},
    {:dh_dss, :aes_128_cbc, :sha},
    {:dh_rsa, :aes_128_cbc, :sha},
    {:dhe_dss, :aes_128_cbc, :sha},
    {:dhe_rsa, :aes_128_cbc, :sha},
    {:dh_anon, :aes_128_cbc, :sha},
    {:rsa, :aes_256_cbc, :sha},
    {:dh_dss, :aes_256_cbc, :sha},
    {:dh_rsa, :aes_256_cbc, :sha},
    {:dhe_dss, :aes_256_cbc, :sha},
    {:dhe_rsa, :aes_256_cbc, :sha},
    {:dh_anon, :aes_256_cbc, :sha},
    {:rsa, :null, :sha256},
    {:rsa, :aes_128_cbc, :sha256},
    {:rsa, :aes_256_cbc, :sha256},
    {:dh_dss, :aes_128_cbc, :sha256},
    {:dh_rsa, :aes_128_cbc, :sha256},
    {:dhe_dss, :aes_128_cbc, :sha256},
    {:rsa, :camellia_128_cbc, :sha},
    {:dh_dss, :camellia_128_cbc, :sha},
    {:dh_rsa, :camellia_128_cbc, :sha},
    {:dhe_dss, :camellia_128_cbc, :sha},
    {:dhe_rsa, :camellia_128_cbc, :sha},
    {:dh_anon, :camellia_128_cbc, :sha},
    {:dhe_rsa, :aes_128_cbc, :sha256},
    {:dh_dss, :aes_256_cbc, :sha256},
    {:dh_rsa, :aes_256_cbc, :sha256},
    {:dhe_dss, :aes_256_cbc, :sha256},
    {:dhe_rsa, :aes_256_cbc, :sha256},
    {:dh_anon, :aes_128_cbc, :sha256},
    {:dh_anon, :aes_256_cbc, :sha256},
    {:rsa, :camellia_256_cbc, :sha},
    {:dh_dss, :camellia_256_cbc, :sha},
    {:dh_rsa, :camellia_256_cbc, :sha},
    {:dhe_dss, :camellia_256_cbc, :sha},
    {:dhe_rsa, :camellia_256_cbc, :sha},
    {:dh_anon, :camellia_256_cbc, :sha},
    {:psk, :rc4_128, :sha},
    {:psk, :"3des_ede_cbc", :sha},
    {:psk, :aes_128_cbc, :sha},
    {:psk, :aes_256_cbc, :sha},
    {:dhe_psk, :rc4_128, :sha},
    {:dhe_psk, :"3des_ede_cbc", :sha},
    {:dhe_psk, :aes_128_cbc, :sha},
    {:dhe_psk, :aes_256_cbc, :sha},
    {:rsa_psk, :rc4_128, :sha},
    {:rsa_psk, :"3des_ede_cbc", :sha},
    {:rsa_psk, :aes_128_cbc, :sha},
    {:rsa_psk, :aes_256_cbc, :sha},
    {:rsa, :seed_cbc, :sha},
    {:dh_dss, :seed_cbc, :sha},
    {:dh_rsa, :seed_cbc, :sha},
    {:dhe_dss, :seed_cbc, :sha},
    {:dhe_rsa, :seed_cbc, :sha},
    {:dh_anon, :seed_cbc, :sha},
    {:rsa, :aes_128_gcm, :sha256},
    {:rsa, :aes_256_gcm, :sha384},
    {:dh_rsa, :aes_128_gcm, :sha256},
    {:dh_rsa, :aes_256_gcm, :sha384},
    {:dh_dss, :aes_128_gcm, :sha256},
    {:dh_dss, :aes_256_gcm, :sha384},
    {:dh_anon, :aes_128_gcm, :sha256},
    {:dh_anon, :aes_256_gcm, :sha384},
    {:psk, :aes_128_gcm, :sha256},
    {:psk, :aes_256_gcm, :sha384},
    {:rsa_psk, :aes_128_gcm, :sha256},
    {:rsa_psk, :aes_256_gcm, :sha384},
    {:psk, :aes_128_cbc, :sha256},
    {:psk, :aes_256_cbc, :sha384},
    {:psk, :null, :sha256},
    {:psk, :null, :sha384},
    {:dhe_psk, :aes_128_cbc, :sha256},
    {:dhe_psk, :aes_256_cbc, :sha384},
    {:dhe_psk, :null, :sha256},
    {:dhe_psk, :null, :sha384},
    {:rsa_psk, :aes_128_cbc, :sha256},
    {:rsa_psk, :aes_256_cbc, :sha384},
    {:rsa_psk, :null, :sha256},
    {:rsa_psk, :null, :sha384},
    {:rsa, :camellia_128_cbc, :sha256},
    {:dh_dss, :camellia_128_cbc, :sha256},
    {:dh_rsa, :camellia_128_cbc, :sha256},
    {:dhe_dss, :camellia_128_cbc, :sha256},
    {:dhe_rsa, :camellia_128_cbc, :sha256},
    {:dh_anon, :camellia_128_cbc, :sha256},
    {:rsa, :camellia_256_cbc, :sha256},
    {:dh_dss, :camellia_256_cbc, :sha256},
    {:dh_rsa, :camellia_256_cbc, :sha256},
    {:dhe_dss, :camellia_256_cbc, :sha256},
    {:dhe_rsa, :camellia_256_cbc, :sha256},
    {:dh_anon, :camellia_256_cbc, :sha256},
    {:ecdh_ecdsa, :null, :sha},
    {:ecdh_ecdsa, :rc4_128, :sha},
    {:ecdh_ecdsa, :"3des_ede_cbc", :sha},
    {:ecdh_ecdsa, :aes_128_cbc, :sha},
    {:ecdh_ecdsa, :aes_256_cbc, :sha},
    {:ecdhe_ecdsa, :null, :sha},
    {:ecdhe_ecdsa, :rc4_128, :sha},
    {:ecdhe_ecdsa, :"3des_ede_cbc", :sha},
    {:ecdhe_ecdsa, :aes_128_cbc, :sha},
    {:ecdhe_ecdsa, :aes_256_cbc, :sha},
    {:ecdh_rsa, :null, :sha},
    {:ecdh_rsa, :rc4_128, :sha},
    {:ecdh_rsa, :"3des_ede_cbc", :sha},
    {:ecdh_rsa, :aes_128_cbc, :sha},
    {:ecdh_rsa, :aes_256_cbc, :sha},
    {:ecdhe_rsa, :null, :sha},
    {:ecdhe_rsa, :rc4_128, :sha},
    {:ecdhe_rsa, :"3des_ede_cbc", :sha},
    {:ecdhe_rsa, :aes_128_cbc, :sha},
    {:ecdhe_rsa, :aes_256_cbc, :sha},
    {:ecdh_anon, :null, :sha},
    {:ecdh_anon, :rc4_128, :sha},
    {:ecdh_anon, :"3des_ede_cbc", :sha},
    {:ecdh_anon, :aes_128_cbc, :sha},
    {:ecdh_anon, :aes_256_cbc, :sha},
    {:srp_sha, :"3des_ede_cbc", :sha},
    {:srp_sha_rsa, :"3des_ede_cbc", :sha},
    {:srp_sha_dss, :"3des_ede_cbc", :sha},
    {:srp_sha, :aes_128_cbc, :sha},
    {:srp_sha_rsa, :aes_128_cbc, :sha},
    {:srp_sha_dss, :aes_128_cbc, :sha},
    {:srp_sha, :aes_256_cbc, :sha},
    {:srp_sha_rsa, :aes_256_cbc, :sha},
    {:srp_sha_dss, :aes_256_cbc, :sha},
    {:ecdhe_ecdsa, :aes_128_cbc, :sha256},
    {:ecdhe_ecdsa, :aes_256_cbc, :sha384},
    {:ecdh_ecdsa, :aes_128_cbc, :sha256},
    {:ecdh_ecdsa, :aes_256_cbc, :sha384},
    {:ecdhe_rsa, :aes_128_cbc, :sha256},
    {:ecdhe_rsa, :aes_256_cbc, :sha384},
    {:ecdh_rsa, :aes_128_cbc, :sha256},
    {:ecdh_rsa, :aes_256_cbc, :sha384},
    {:ecdh_ecdsa, :aes_128_gcm, :sha256},
    {:ecdh_ecdsa, :aes_256_gcm, :sha384},
    {:ecdh_rsa, :aes_128_gcm, :sha256},
    {:ecdh_rsa, :aes_256_gcm, :sha384},
    {:ecdhe_psk, :rc4_128, :sha},
    {:ecdhe_psk, :"3des_ede_cbc", :sha},
    {:ecdhe_psk, :aes_128_cbc, :sha},
    {:ecdhe_psk, :aes_256_cbc, :sha},
    {:ecdhe_psk, :aes_128_cbc, :sha256},
    {:ecdhe_psk, :aes_256_cbc, :sha384},
    {:ecdhe_psk, :null, :sha},
    {:ecdhe_psk, :null, :sha256},
    {:ecdhe_psk, :null, :sha384},
    {:rsa, :aria_128_cbc, :sha256},
    {:rsa, :aria_256_cbc, :sha384},
    {:dh_dss, :aria_128_cbc, :sha256},
    {:dh_dss, :aria_256_cbc, :sha384},
    {:dh_rsa, :aria_128_cbc, :sha256},
    {:dh_rsa, :aria_256_cbc, :sha384},
    {:dhe_dss, :aria_128_cbc, :sha256},
    {:dhe_dss, :aria_256_cbc, :sha384},
    {:dhe_rsa, :aria_128_cbc, :sha256},
    {:dhe_rsa, :aria_256_cbc, :sha384},
    {:dh_anon, :aria_128_cbc, :sha256},
    {:dh_anon, :aria_256_cbc, :sha384},
    {:ecdhe_ecdsa, :aria_128_cbc, :sha256},
    {:ecdhe_ecdsa, :aria_256_cbc, :sha384},
    {:ecdh_ecdsa, :aria_128_cbc, :sha256},
    {:ecdh_ecdsa, :aria_256_cbc, :sha384},
    {:ecdhe_rsa, :aria_128_cbc, :sha256},
    {:ecdhe_rsa, :aria_256_cbc, :sha384},
    {:ecdh_rsa, :aria_128_cbc, :sha256},
    {:ecdh_rsa, :aria_256_cbc, :sha384},
    {:rsa, :aria_128_gcm, :sha256},
    {:rsa, :aria_256_gcm, :sha384},
    {:dh_rsa, :aria_128_gcm, :sha256},
    {:dh_rsa, :aria_256_gcm, :sha384},
    {:dh_dss, :aria_128_gcm, :sha256},
    {:dh_dss, :aria_256_gcm, :sha384},
    {:dh_anon, :aria_128_gcm, :sha256},
    {:dh_anon, :aria_256_gcm, :sha384},
    {:ecdh_ecdsa, :aria_128_gcm, :sha256},
    {:ecdh_ecdsa, :aria_256_gcm, :sha384},
    {:ecdh_rsa, :aria_128_gcm, :sha256},
    {:ecdh_rsa, :aria_256_gcm, :sha384},
    {:psk, :aria_128_cbc, :sha256},
    {:psk, :aria_256_cbc, :sha384},
    {:dhe_psk, :aria_128_cbc, :sha256},
    {:dhe_psk, :aria_256_cbc, :sha384},
    {:rsa_psk, :aria_128_cbc, :sha256},
    {:rsa_psk, :aria_256_cbc, :sha384},
    {:psk, :aria_128_gcm, :sha256},
    {:psk, :aria_256_gcm, :sha384},
    {:rsa_psk, :aria_128_gcm, :sha256},
    {:rsa_psk, :aria_256_gcm, :sha384},
    {:ecdhe_psk, :aria_128_cbc, :sha256},
    {:ecdhe_psk, :aria_256_cbc, :sha384},
    {:ecdhe_ecdsa, :camellia_128_cbc, :sha256},
    {:ecdhe_ecdsa, :camellia_256_cbc, :sha384},
    {:ecdh_ecdsa, :camellia_128_cbc, :sha256},
    {:ecdh_ecdsa, :camellia_256_cbc, :sha384},
    {:ecdhe_rsa, :camellia_128_cbc, :sha256},
    {:ecdhe_rsa, :camellia_256_cbc, :sha384},
    {:ecdh_rsa, :camellia_128_cbc, :sha256},
    {:ecdh_rsa, :camellia_256_cbc, :sha384},
    {:rsa, :camellia_128_gcm, :sha256},
    {:rsa, :camellia_256_gcm, :sha384},
    {:dh_rsa, :camellia_128_gcm, :sha256},
    {:dh_rsa, :camellia_256_gcm, :sha384},
    {:dh_dss, :camellia_128_gcm, :sha256},
    {:dh_dss, :camellia_256_gcm, :sha384},
    {:dh_anon, :camellia_128_gcm, :sha256},
    {:dh_anon, :camellia_256_gcm, :sha384},
    {:ecdh_ecdsa, :camellia_128_gcm, :sha256},
    {:ecdh_ecdsa, :camellia_256_gcm, :sha384},
    {:ecdh_rsa, :camellia_128_gcm, :sha256},
    {:ecdh_rsa, :camellia_256_gcm, :sha384},
    {:psk, :camellia_128_gcm, :sha256},
    {:psk, :camellia_256_gcm, :sha384},
    {:rsa_psk, :camellia_128_gcm, :sha256},
    {:rsa_psk, :camellia_256_gcm, :sha384},
    {:psk, :camellia_128_cbc, :sha256},
    {:psk, :camellia_256_cbc, :sha384},
    {:dhe_psk, :camellia_128_cbc, :sha256},
    {:dhe_psk, :camellia_256_cbc, :sha384},
    {:rsa_psk, :camellia_128_cbc, :sha256},
    {:rsa_psk, :camellia_256_cbc, :sha384},
    {:ecdhe_psk, :camellia_128_cbc, :sha256},
    {:ecdhe_psk, :camellia_256_cbc, :sha384},
    {:rsa, :aes_128, :ccm},
    {:rsa, :aes_256, :ccm},
    {:rsa, :aes_128, :ccm_8},
    {:rsa, :aes_256, :ccm_8},
    {:psk, :aes_128, :ccm},
    {:psk, :aes_256, :ccm},
    {:psk, :aes_128, :ccm_8},
    {:psk, :aes_256, :ccm_8}
  ]

  @transport_opts [
    packet: :raw,
    mode: :binary,
    active: false
  ]

  @default_versions [:"tlsv1.2"]
  @default_timeout 30_000

  Record.defrecordp(
    :certificate,
    :Certificate,
    Record.extract(:Certificate, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  Record.defrecordp(
    :tbs_certificate,
    :OTPTBSCertificate,
    Record.extract(:OTPTBSCertificate, from_lib: "public_key/include/OTP-PUB-KEY.hrl")
  )

  # TODO: Document how to enable revocation checking:
  #       crl_check: true
  #       crl_cache: {:ssl_crl_cache, {:internal, [http: 30_000]}}

  @impl true
  def connect(hostname, port, opts) do
    hostname = String.to_charlist(hostname)
    timeout = Keyword.get(opts, :timeout, @default_timeout)

    wrap_err(:ssl.connect(hostname, port, ssl_opts(hostname, opts), timeout))
  end

  @impl true
  def upgrade(socket, :http, hostname, _port, opts) do
    hostname = String.to_charlist(hostname)
    timeout = Keyword.get(opts, :timeout, @default_timeout)

    # Seems like this is not set in :ssl.connect/2 correctly, so set it explicitly
    Mint.Core.Transport.TCP.setopts(socket, active: false)

    wrap_err(:ssl.connect(socket, ssl_opts(hostname, opts), timeout))
  end

  def upgrade(_socket, :https, _hostname, _port, _opts) do
    raise "nested SSL sessions are not supported"
  end

  @impl true
  def negotiated_protocol(socket) do
    wrap_err(:ssl.negotiated_protocol(socket))
  end

  @impl true
  def send(socket, payload) do
    wrap_err(:ssl.send(socket, payload))
  end

  @impl true
  def close(socket) do
    wrap_err(:ssl.close(socket))
  end

  @impl true
  def recv(socket, bytes, timeout) do
    wrap_err(:ssl.recv(socket, bytes, timeout))
  end

  @impl true
  def controlling_process(socket, pid) do
    # We do this dance because it's what gen_tcp does in Erlang. However, ssl
    # doesn't do this so we need to do it ourselves. Implementation roughly
    # taken from this:
    # https://github.com/erlang/otp/blob/fc1f0444e32b039194189af97fb3d5358a2b91e3/lib/kernel/src/inet.erl#L1696-L1754
    with {:ok, active: active} <- getopts(socket, [:active]),
         :ok <- setopts(socket, active: false),
         :ok <- forward_messages_to_new_controlling_process(socket, pid),
         :ok <- wrap_err(:ssl.controlling_process(socket, pid)) do
      if(active == :once, do: setopts(socket, active: :once), else: :ok)
    end
  end

  defp forward_messages_to_new_controlling_process(socket, pid) do
    receive do
      {:ssl, ^socket, _data} = message ->
        Kernel.send(pid, message)
        forward_messages_to_new_controlling_process(socket, pid)

      {:ssl_error, ^socket, error} ->
        {:error, error}

      {:ssl_closed, ^socket} ->
        {:error, :closed}
    after
      0 ->
        :ok
    end
  end

  @impl true
  def setopts(socket, opts) do
    wrap_err(:ssl.setopts(socket, opts))
  end

  @impl true
  def getopts(socket, opts) do
    wrap_err(:ssl.getopts(socket, opts))
  end

  @impl true
  def wrap_error(reason) do
    %Mint.TransportError{reason: reason}
  end

  defp ssl_opts(hostname, opts) do
    default_ssl_opts(hostname)
    |> Keyword.merge(opts)
    |> Keyword.merge(@transport_opts)
    |> Keyword.delete(:timeout)
    |> add_verify_opts(hostname)
  end

  defp add_verify_opts(opts, hostname) do
    verify = Keyword.get(opts, :verify)

    if verify == :verify_peer do
      opts
      |> add_cacerts()
      |> add_partial_chain_fun()
      |> customize_hostname_check(hostname)
    else
      opts
    end
  end

  defp customize_hostname_check(opts, host_or_ip) do
    if ssl_major_version() >= 9 do
      # From OTP 20.0 use built-in support for custom hostname checks
      add_customize_hostname_check(opts)
    else
      # Before OTP 20.0 use mint_shims for hostname check, from a custom
      # verify_fun
      add_verify_fun(opts, host_or_ip)
    end
  end

  defp add_customize_hostname_check(opts) do
    customize_hostname_check_present? = Keyword.has_key?(opts, :customize_hostname_check)

    if not customize_hostname_check_present? do
      Keyword.put(opts, :customize_hostname_check, match_fun: &match_fun/2)
    else
      opts
    end
  end

  defp add_verify_fun(opts, host_or_ip) do
    verify_fun_present? = Keyword.has_key?(opts, :verify_fun)

    if not verify_fun_present? do
      reference_ids = [dns_id: host_or_ip, ip: host_or_ip]
      Keyword.put(opts, :verify_fun, {&verify_fun/3, reference_ids})
    else
      opts
    end
  end

  def verify_fun(_, {:bad_cert, _} = reason, _), do: {:fail, reason}
  def verify_fun(_, {:extension, _}, state), do: {:unknown, state}
  def verify_fun(_, :valid, state), do: {:valid, state}

  def verify_fun(cert, :valid_peer, state) do
    if :mint_shims.pkix_verify_hostname(cert, state, match_fun: &match_fun/2) do
      {:valid, state}
    else
      {:fail, {:bad_cert, :hostname_check_failed}}
    end
  end

  # Wildcard domain handling for DNS ID entries in the subjectAltName X.509
  # extension. Note that this is a subset of the wildcard patterns implemented
  # by OTP when matching against the subject CN attribute, but this is the only
  # wildcard usage defined by the CA/Browser Forum's Baseline Requirements, and
  # therefore the only pattern used in commercially issued certificates.
  defp match_fun({:dns_id, reference}, {:dNSName, [?*, ?. | presented]}) do
    case domain_without_host(reference) do
      '' ->
        :default

      domain ->
        # TODO: replace with `:string.casefold/1` eventually
        :string.to_lower(domain) == :string.to_lower(presented)
    end
  end

  defp match_fun(_reference, _presented), do: :default

  defp domain_without_host([]), do: []
  defp domain_without_host([?. | domain]), do: domain
  defp domain_without_host([_ | more]), do: domain_without_host(more)

  defp default_ssl_opts(hostname) do
    # TODO: Add revocation check

    [
      ciphers: default_ciphers(),
      server_name_indication: hostname,
      versions: @default_versions,
      verify: :verify_peer,
      depth: 4,
      secure_renegotiate: true,
      reuse_sessions: true
    ]
  end

  defp add_cacerts(opts) do
    if Keyword.has_key?(opts, :cacertfile) || Keyword.has_key?(opts, :cacerts) do
      opts
    else
      raise_on_missing_castore!()
      Keyword.put(opts, :cacertfile, CAStore.file_path())
    end
  end

  defp add_partial_chain_fun(opts) do
    if Keyword.has_key?(opts, :partial_chain) do
      opts
    else
      case Keyword.fetch(opts, :cacerts) do
        {:ok, cacerts} ->
          cacerts = decode_cacerts(cacerts)
          fun = &partial_chain(cacerts, &1)
          Keyword.put(opts, :partial_chain, fun)

        :error ->
          path = Keyword.fetch!(opts, :cacertfile)
          cacerts = decode_cacertfile(path)
          fun = &partial_chain(cacerts, &1)
          Keyword.put(opts, :partial_chain, fun)
      end
    end
  end

  defp decode_cacertfile(path) do
    # TODO: Cache this?

    path
    |> File.read!()
    |> :public_key.pem_decode()
    |> Enum.filter(&match?({:Certificate, _, :not_encrypted}, &1))
    |> Enum.map(&:public_key.pem_entry_decode/1)
  end

  defp decode_cacerts(certs) do
    # TODO: Cache this?

    Enum.map(certs, &:public_key.pkix_decode_cert(&1, :plain))
  end

  def partial_chain(cacerts, certs) do
    # TODO: Shim this with OTP 21.1 implementation?

    certs = Enum.map(certs, &{&1, :public_key.pkix_decode_cert(&1, :plain)})

    trusted =
      Enum.find_value(certs, fn {der, cert} ->
        trusted? =
          Enum.find(cacerts, fn cacert ->
            extract_public_key_info(cacert) == extract_public_key_info(cert)
          end)

        if trusted?, do: der
      end)

    if trusted do
      {:trusted_ca, trusted}
    else
      :unknown_ca
    end
  end

  defp extract_public_key_info(cert) do
    cert
    |> certificate(:tbsCertificate)
    |> tbs_certificate(:subjectPublicKeyInfo)
  end

  # NOTE: Should this be private and moved to a different module?
  @doc false
  def default_ciphers(), do: get_valid_suites(:ssl.cipher_suites(), [])

  @dialyzer {:no_match, get_valid_suites: 2}

  for {kex, cipher, mac} <- @blacklisted_ciphers do
    defp get_valid_suites([{unquote(kex), unquote(cipher), _mac, unquote(mac)} | rest], valid) do
      get_valid_suites(rest, valid)
    end

    defp get_valid_suites([{unquote(kex), unquote(cipher), unquote(mac)} | rest], valid) do
      get_valid_suites(rest, valid)
    end
  end

  defp get_valid_suites([suit | rest], valid), do: get_valid_suites(rest, [suit | valid])
  defp get_valid_suites([], valid), do: valid

  defp raise_on_missing_castore! do
    Code.ensure_loaded?(CAStore) ||
      raise "default CA trust store not available; " <>
              "please add `:castore` to your project's dependencies or " <>
              "specify the trust store using the `:cacertfile`/`:cacerts` option"
  end

  defp wrap_err({:error, reason}), do: {:error, wrap_error(reason)}
  defp wrap_err(other), do: other

  defp ssl_major_version do
    Application.spec(:ssl, :vsn)
    |> :string.to_integer()
    |> elem(0)
  end
end
