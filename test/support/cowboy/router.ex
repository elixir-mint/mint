defmodule Mint.CowboyTestServer.PlugRouter do
  @moduledoc false

  use Plug.Router

  plug(:match)

  plug(
    Plug.Parsers,
    parsers: [:urlencoded, :multipart, :json],
    pass: ["*/*"],
    json_decoder: Jason
  )

  plug(Plug.Static, at: "/static", from: Path.absname("./static", __DIR__))

  plug(:dispatch)

  get "/" do
    name = conn.params["name"] || "world"
    send_resp(conn, 200, "Hello #{name}!")
  end

  get "/bytes/:size" do
    size = min(String.to_integer(size), 100 * 1024)
    bytes = :crypto.strong_rand_bytes(size)
    send_resp(conn, 200, bytes)
  end

  post "/post" do
    {:ok, body, conn} = Plug.Conn.read_body(conn)
    send_resp(conn, 200, body)
  end

  get "/stream-bytes/:size" do
    chunk_size = conn.params["chunk_size"]
    chunk_size = if chunk_size != nil, do: String.to_integer(chunk_size), else: 10 * 1024

    conn = Plug.Conn.send_chunked(conn, 200)

    size
    |> String.to_integer()
    |> min(100 * 1024)
    |> :crypto.strong_rand_bytes()
    |> :binary.bin_to_list()
    |> Enum.chunk_every(chunk_size)
    |> Enum.reduce_while(conn, fn chunk, conn ->
      chunk_bytes = :binary.list_to_bin(chunk)

      case Plug.Conn.chunk(conn, chunk_bytes) do
        {:ok, conn} ->
          {:cont, conn}

        {:error, :closed} ->
          {:halt, conn}
      end
    end)
  end

  get "/reqinfo" do
    body =
      "Method: #{conn.method}\nProtocol: #{get_http_protocol(conn)}\nRequestURI: #{
        conn.request_path
      }\n\nHeaders:\n#{inspect(conn.req_headers)}"

    send_resp(conn, 200, body)
  end

  get "/clockstream" do
    conn = send_chunked(conn, 200)

    content =
      "# ~1KB of junk to force browsers to start rendering immediately: \n" <>
        String.duplicate(
          "# xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n",
          13
        )

    {:ok, conn} = chunk(conn, content)

    send_clock(conn)
  end

  defp send_clock(conn) do
    Process.sleep(1_000)
    now = NaiveDateTime.to_string(NaiveDateTime.utc_now())
    content = "#{now} +0000 UTC\n"
    {:ok, conn} = chunk(conn, content)
    send_clock(conn)
  end

  put "/echo" do
    conn = send_chunked(conn, 200)
    {:ok, body, conn} = Plug.Conn.read_body(conn)
    {:ok, conn} = chunk(conn, String.upcase(body))
    conn
  end

  get "/file/gopher.png" do
    filename = Path.absname("./static/image/gopher.png", __DIR__)
    file = File.read!(filename)
    conn = send_chunked(conn, 200)
    {:ok, conn} = chunk(conn, file)
    conn
  end

  get "/serverpush" do
    body = "<!DOCTYPE html>
    <html lang=\"en\">
      <body>
        <img src=\"/static/image/gopher.png\">
      </body>
    </html>"

    conn
    |> push("/static/image/gopher.png", [{"accept", "image/png"}])
    |> push("/static/image/gopher.png", [{"accept", "image/png"}])
    |> push("/static/image/gopher.png", [{"accept", "image/png"}])
    |> push("/static/image/gopher.png", [{"accept", "image/png"}])
    |> send_resp(200, body)
  end

  get "/301-redirect" do
    conn
    |> put_resp_header("location", "/")
    |> send_resp(301, "")
  end

  get "/feed" do
    if_modified_since_lable = "if-modified-since"

    case List.keyfind(conn.req_headers, if_modified_since_lable, 0) do
      {^if_modified_since_lable, "Wed, 26 May 2019 07:43:40 GMT"} ->
        send_resp(conn, 304, "")

      _ ->
        send_resp(conn, 200, "")
    end
  end

  match _ do
    send_resp(conn, 404, "oops")
  end
end
