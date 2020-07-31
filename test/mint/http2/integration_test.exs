defmodule Mint.HTTP2.IntegrationTest do
  use ExUnit.Case, async: true

  import Mint.HTTP2.TestHelpers

  alias Mint.HTTP2

  @moduletag :integration

  @port_http 8101
  @port_https 8202

  test "TCP" do
    assert {:ok, %HTTP2{} = conn} = HTTP2.connect(:http, "localhost", @port_http)

    assert {:ok, %HTTP2{} = conn, ref} = HTTP2.request(conn, "GET", "/", [], nil)

    assert {:ok, %HTTP2{} = conn, responses} = receive_stream(conn)

    assert [{:status, ^ref, status}, {:headers, ^ref, headers} | rest] = responses
    assert {_, [{:done, ^ref}]} = Enum.split_while(rest, &match?({:data, ^ref, _}, &1))

    assert status == 200
    assert is_list(headers)

    assert conn.buffer == ""
    assert HTTP2.open?(conn)
  end

  describe "SSL" do
    test "GET /reqinfo" do
      assert {:ok, %HTTP2{} = conn} =
               HTTP2.connect(:https, "localhost", @port_https,
                 transport_opts: [verify: :verify_none]
               )

      assert {:ok, %HTTP2{} = conn, req_id} = HTTP2.request(conn, "GET", "/reqinfo", [], nil)

      assert {:ok, %HTTP2{} = conn, responses} = receive_stream(conn)

      assert [
               {:status, ^req_id, 200},
               {:headers, ^req_id, headers},
               {:data, ^req_id, data},
               {:done, ^req_id}
             ] = responses

      assert is_list(headers)
      assert data =~ "Method: GET"

      assert conn.buffer == ""
      assert HTTP2.open?(conn)
    end

    test "GET /clockstream" do
      assert {:ok, %HTTP2{} = conn} =
               HTTP2.connect(:https, "localhost", @port_https,
                 transport_opts: [verify: :verify_none]
               )

      assert {:ok, %HTTP2{} = conn, req_id} = HTTP2.request(conn, "GET", "/clockstream", [], nil)

      assert {:ok, %HTTP2{} = conn, responses} = stream_messages_until_response(conn)

      assert [{:status, ^req_id, 200}, {:headers, ^req_id, _headers} | rest] = responses

      conn =
        if rest != [] do
          assert [{:data, ^req_id, data}] = rest
          assert data =~ "# ~1KB of junk to force browsers to start rendering immediately"
          conn
        else
          assert_receive message, 5000
          assert {:ok, %HTTP2{} = conn, responses} = HTTP2.stream(conn, message)
          assert [{:data, ^req_id, data}] = responses
          assert data =~ "# ~1KB of junk to force browsers to start rendering immediately"
          conn
        end

      assert_receive message, 5000
      assert {:ok, %HTTP2{} = conn, responses} = HTTP2.stream(conn, message)
      assert [{:data, ^req_id, data}] = responses
      assert data =~ ~r/\A\d{4}-\d{2}-\d{2}/

      assert HTTP2.open?(conn)
    end

    test "PUT /echo" do
      assert {:ok, %HTTP2{} = conn} =
               HTTP2.connect(:https, "localhost", @port_https,
                 transport_opts: [verify: :verify_none]
               )

      assert {:ok, %HTTP2{} = conn, req_id} =
               HTTP2.request(conn, "PUT", "/echo", [], "hello world")

      assert {:ok, %HTTP2{} = conn, responses} = receive_stream(conn)

      assert [
               {:status, ^req_id, 200},
               {:headers, ^req_id, headers},
               {:data, ^req_id, data},
               {:data, ^req_id, ""},
               {:done, ^req_id}
             ] = responses

      assert is_list(headers)
      assert data == "HELLO WORLD"

      assert conn.buffer == ""
      assert HTTP2.open?(conn)
    end

    test "GET /file/gopher.png" do
      assert {:ok, %HTTP2{} = conn} =
               HTTP2.connect(:https, "localhost", @port_https,
                 transport_opts: [verify: :verify_none]
               )

      assert {:ok, %HTTP2{} = conn, ref} = HTTP2.request(conn, "GET", "/file/gopher.png", [], nil)
      assert {:ok, %HTTP2{} = conn, responses} = receive_stream(conn)

      assert [
               {:status, ^ref, 200},
               {:headers, ^ref, headers},
               {:data, ^ref, data1},
               {:data, ^ref, data2},
               {:data, ^ref, data3},
               {:done, ^ref}
             ] = responses

      assert is_list(headers)
      assert is_binary(data1)
      assert is_binary(data2)
      assert is_binary(data3)

      assert conn.buffer == ""
      assert HTTP2.open?(conn)
    end

    test "ping" do
      assert {:ok, %HTTP2{} = conn} =
               HTTP2.connect(:https, "localhost", @port_https,
                 transport_opts: [verify: :verify_none]
               )

      assert {:ok, %HTTP2{} = conn, ref} = HTTP2.ping(conn)
      assert {:ok, %HTTP2{} = conn, [{:pong, ^ref}]} = receive_stream(conn)
      assert conn.buffer == ""
      assert HTTP2.open?(conn)
    end

    test "GET /serverpush" do
      assert {:ok, %HTTP2{} = conn} =
               HTTP2.connect(:https, "localhost", @port_https,
                 transport_opts: [verify: :verify_none]
               )

      assert {:ok, %HTTP2{} = conn, req_id} = HTTP2.request(conn, "GET", "/serverpush", [], nil)
      assert {:ok, %HTTP2{} = _conn, responses} = receive_stream(conn)

      # TODO: improve this test by improving receive_stream/1.
      assert [
               {:push_promise, ^req_id, _promised_req_id1, _headers1},
               {:push_promise, ^req_id, _promised_req_id2, _headers2},
               {:push_promise, ^req_id, _promised_req_id3, _headers3},
               {:push_promise, ^req_id, _promised_req_id4, _headers4} | _
             ] = responses
    end

    test "GET /" do
      assert {:ok, %HTTP2{} = conn} =
               HTTP2.connect(:https, "localhost", @port_https,
                 transport_opts: [verify: :verify_none]
               )

      assert {:ok, %HTTP2{} = conn, ref} = HTTP2.request(conn, "GET", "/", [], nil)

      assert {:ok, %HTTP2{} = conn, responses} = receive_stream(conn)

      assert [{:status, ^ref, status}, {:headers, ^ref, headers} | rest] = responses
      assert {_, [{:done, ^ref}]} = Enum.split_while(rest, &match?({:data, ^ref, _}, &1))

      assert status == 200
      assert is_list(headers)

      assert conn.buffer == ""
      assert HTTP2.open?(conn)
    end

    test "GET /301-redirect" do
      assert {:ok, %HTTP2{} = conn} =
               HTTP2.connect(:https, "localhost", @port_https,
                 transport_opts: [verify: :verify_none]
               )

      assert {:ok, %HTTP2{} = conn, ref} = HTTP2.request(conn, "GET", "/301-redirect", [], nil)

      assert {:ok, %HTTP2{} = conn, responses} = receive_stream(conn)

      assert [{:status, ^ref, status}, {:headers, ^ref, headers} | rest] = responses
      assert {_, [{:done, ^ref}]} = Enum.split_while(rest, &match?({:data, ^ref, _}, &1))

      assert status == 301
      assert is_list(headers)

      assert conn.buffer == ""
      assert HTTP2.open?(conn)
    end

    test "GET /feed/ - regression for #171" do
      assert {:ok, %HTTP2{} = conn} =
               HTTP2.connect(:https, "localhost", @port_https,
                 transport_opts: [verify: :verify_none]
               )

      # Using non-downcased header meant that HPACK wouldn't find it in the
      # static built-in headers table and so it wouldn't encode it correctly.
      headers = [{"If-Modified-Since", "Wed, 26 May 2019 07:43:40 GMT"}]
      assert {:ok, %HTTP2{} = conn, ref} = HTTP2.request(conn, "GET", "/feed", headers, nil)

      assert {:ok, %HTTP2{} = conn, responses} = receive_stream(conn)

      assert [{:status, ^ref, status}, {:headers, ^ref, _headers} | rest] = responses
      assert {_, [{:done, ^ref}]} = Enum.split_while(rest, &match?({:data, ^ref, _}, &1))

      assert status == 304

      assert conn.buffer == ""
      assert HTTP2.open?(conn)

      headers = [{"If-Modified-Since", "Tue, 26 May 2020 07:43:40 GMT"}]
      assert {:ok, %HTTP2{} = conn, ref} = HTTP2.request(conn, "GET", "/feed", headers, nil)

      assert {:ok, %HTTP2{} = conn, responses} = receive_stream(conn)

      assert [{:status, ^ref, status}, {:headers, ^ref, _headers} | rest] = responses
      assert {_, [{:done, ^ref}]} = Enum.split_while(rest, &match?({:data, ^ref, _}, &1))

      assert status == 200

      assert conn.buffer == ""
      assert HTTP2.open?(conn)
    end
  end

  defp stream_messages_until_response(conn) do
    assert_receive message, 1000

    case HTTP2.stream(conn, message) do
      {:ok, %HTTP2{} = conn, []} -> stream_messages_until_response(conn)
      other -> other
    end
  end

  # TODO: certificate verification; badssl.com does not seem to support HTTP2
end
