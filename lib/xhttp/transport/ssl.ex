defmodule XHTTP.Transport.SSL do
  require Logger

  @behaviour XHTTP.Transport

  @default_ssl_opts [verify: :verify_peer]

  # Hostname check was enabled in the ssl application in OTP-20.0-rc2:
  # https://github.com/erlang/otp/blob/d106c5fffb3832fffbdf99cca905390fe15d489f/lib/ssl/vsn.mk
  @verify_hostname_ssl_vsn [8, 2]

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

    if verify == :verify_peer and not verify_fun_present? and use_pkix_verify_hostname_shim?() do
      Logger.debug("ssl application does not perform hostname verifaction; activating shim")

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

  defp use_pkix_verify_hostname_shim?() do
    ssl_vsn() < @verify_hostname_ssl_vsn
  end

  defp ssl_vsn() do
    {:ok, vsn} = :application.get_key(:ssl, :vsn)
    vsn |> :string.tokens('.') |> Enum.map(&List.to_integer/1)
  end

  defp verify_fun(_, {:bad_cert, _} = reason, _), do: {:fail, reason}
  defp verify_fun(_, {:extension, _}, state), do: {:unknown, state}
  defp verify_fun(_, :valid, state), do: {:valid, state}

  defp verify_fun(cert, :valid_peer, state) do
    if :xhttp_shims.pkix_verify_hostname(cert, state) do
      {:valid, state}
    else
      {:fail, {:bad_cert, :hostname_check_failed}}
    end
  end
end
