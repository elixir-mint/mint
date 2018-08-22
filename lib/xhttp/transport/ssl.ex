defmodule XHTTP.Transport.SSL do
  require Logger

  @behaviour XHTTP.Transport

  @default_ssl_opts [verify: :verify_peer]

  @impl true
  def connect(host, port, opts) do
    ssl_opts =
      @default_ssl_opts
      |> Keyword.merge(opts)
      |> update_ssl_opts(host)

    host
    |> String.to_charlist()
    |> :ssl.connect(port, ssl_opts)
  end

  @impl true
  defdelegate negotiated_protocol(socket), to: :ssl

  @impl true
  def send(socket, payload) do
    with :ok <- :ssl.send(socket, payload) do
      {:ok, socket}
    end
  end

  @impl true
  def close(socket) do
    with :ok <- :ssl.close(socket) do
      {:ok, socket}
    end
  end

  @impl true
  def recv(socket, bytes) do
    with {:ok, data} <- :ssl.recv(socket, bytes) do
      {:ok, data, socket}
    end
  end

  @impl true
  defdelegate setopts(socket, opts), to: :ssl

  @impl true
  defdelegate getopts(socket, opts), to: :ssl

  defp update_ssl_opts(opts, host_or_ip) do
    verify = Keyword.get(opts, :verify)
    verify_fun_present? = Keyword.has_key?(opts, :verify_fun)

    if verify == :verify_peer and not verify_fun_present? do
      reference_ids =
        case Keyword.fetch(opts, :server_name_indication) do
          {:ok, server_name} ->
            [dns_id: server_name]

          :error ->
            host_or_ip = to_charlist(host_or_ip)
            [dns_id: host_or_ip, ip: host_or_ip]
        end

      Keyword.put(opts, :verify_fun, {&verify_fun/3, reference_ids})
    else
      opts
    end
  end

  def verify_fun(_, {:bad_cert, _} = reason, _), do: {:fail, reason}
  def verify_fun(_, {:extension, _}, state), do: {:unknown, state}
  def verify_fun(_, :valid, state), do: {:valid, state}

  def verify_fun(cert, :valid_peer, state) do
    if :xhttp_shims.pkix_verify_hostname(cert, state, match_fun: &match_fun/2) do
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
end
