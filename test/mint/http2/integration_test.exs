defmodule HTTP2.IntegrationTest do
  use ExUnit.Case, async: true

  import Mint.HTTP2.TestHelpers

  alias Mint.HTTP2
  alias Mint.HttpBin

  setup context do
    transport_opts =
      if Mint.Core.Transport.SSL.ssl_version() >= [10, 2] do
        [{:versions, [:"tlsv1.2", :"tlsv1.3"]}]
      else
        []
      end

    case Map.fetch(context, :connect) do
      {:ok, {host, port}} ->
        extra_transport_opts = Map.get(context, :transport_opts, [])

        assert {:ok, %HTTP2{} = conn} =
                 HTTP2.connect(:https, host, port,
                   transport_opts: transport_opts ++ extra_transport_opts
                 )

        [conn: conn]

      :error ->
        []
    end
  end

  test "TCP - h2c prior knowledge" do
    assert {:ok, %HTTP2{} = conn} = HTTP2.connect(:http, HttpBin.host(), HttpBin.h2c_port())

    assert {:ok, %HTTP2{} = conn, ref} = HTTP2.request(conn, "GET", "/", [], nil)

    assert {:ok, %HTTP2{} = conn, responses} = receive_stream(conn)

    assert [{:status, ^ref, status}, {:headers, ^ref, headers} | rest] = responses
    assert {_, [{:done, ^ref}]} = Enum.split_while(rest, &match?({:data, ^ref, _}, &1))

    assert status == 200
    assert is_list(headers)

    assert conn.buffer == ""
    assert HTTP2.open?(conn)
  end

  describe "httpbin.org" do
    @describetag connect: {HttpBin.host(), HttpBin.https_port()},
                 transport_opts: HttpBin.https_transport_opts()

    test "GET /user-agent", %{conn: conn} do
      assert {:ok, %HTTP2{} = conn, req_id} = HTTP2.request(conn, "GET", "/user-agent", [], nil)

      assert {:ok, %HTTP2{} = conn, responses} = receive_stream(conn)

      assert [
               {:status, ^req_id, 200},
               {:headers, ^req_id, headers},
               {:data, ^req_id, data},
               {:done, ^req_id}
             ] = responses

      assert is_list(headers)
      assert data =~ "mint/"

      assert conn.buffer == ""
      assert HTTP2.open?(conn)
    end

    test "GET /image/png", %{conn: conn} do
      assert {:ok, %HTTP2{} = conn, ref} = HTTP2.request(conn, "GET", "/image/png", [], nil)
      assert {:ok, %HTTP2{} = conn, responses} = receive_stream(conn)

      assert [
               {:status, ^ref, 200},
               {:headers, ^ref, headers},
               {:data, ^ref, data1},
               {:data, ^ref, data2},
               {:done, ^ref}
             ] = responses

      assert is_list(headers)
      assert is_binary(data1)
      assert is_binary(data2)

      assert conn.buffer == ""
      assert HTTP2.open?(conn)
    end

    test "ping", %{conn: conn} do
      assert {:ok, %HTTP2{} = conn, ref} = HTTP2.ping(conn)
      assert {:ok, %HTTP2{} = conn, [{:pong, ^ref}]} = receive_stream(conn)
      assert conn.buffer == ""
      assert HTTP2.open?(conn)
    end
  end
end
