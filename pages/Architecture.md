# Architecture

Mint is an HTTP client with a process-less architecture. Mint provides an API where the HTTP connection is represented by a functional and immutable data structure, a **connection**. Every operation you do on the connection (like sending a request) returns an updated connection. A connection wraps a socket that is in active mode (with `active: :once`). Messages coming from the socket are delivered to the process that created the connection. You can hand those messages to Mint so that they can be parsed into responses.

Having a process-less architecture makes Mint a powerful and composable HTTP client. The developer has more flexibility compared to a client that forces an interface that includes processes. A Mint connection can be stored inside any kind of process, such as GenServers or GenStage processes.

Another important feature enabled by the Mint architecture is that a single process can store and manage multiple Mint connections since they are simple data structures. When a message comes from a socket, it's easy to identify which connection it belongs to since that's the only connection that will return a response different from `:unknown` when the messages are parsed. This enables developers to use Mint in fine-tailored ways that suit their needs.

## Pooling

The Mint connection architecture is low level. This means that it doesn't provide things like connection pooling out of the box. This is by design: it's hard to write a general purpose HTTP connection pool that fits all use cases and it's often better to write simple pools that better fit your own use case. In this page, we'll see a few possible uses of Mint including some simple connection pools that you can use as a base for writing your own.

## Usage examples

Let's see a few example of how to use Mint connections.

### Wrapping a Mint connection in a GenServer

In this example we will look at wrapping a single connection in a GenServer. This architecture can be useful if you only need to issue a few requests to the same host, or if you plan to have many connections spread over just as many processes.

The way this architecture works is that a GenServer process holds the connection. The connection is started when the `ConnectionProcess` GenServer starts (in the `init/1` callback). When a request is made, the request is sent but the GenServer keeps processing stuff and doesn't directly reply to the process that asked to send the request. The GenServer will only reply to the caller once a response comes from the server. This allows the GenServer to keep sending requests and processing responses while making the request blocking for the caller.

This asynchronous architecture also makes the GenServer usable from different processes. If you use HTTP/1, requests will appear to be concurrent to the callers of our GenServer, but the GenServer will pipeline the requests. If you use HTTP/2, the requests will be actually concurrent.
If you want to avoid pipelining requests you need to manually queue them or reject them in case there's already an ongoing request.

In this code we don't handle closed connections and failed requests (for brevity). For example, you could handle closed connections by having the GenServer try to reconnect after a backoff time.

```elixir
defmodule ConnectionProcess do
  use GenServer

  require Logger

  defstruct [:conn, requests: %{}]

  def start_link({scheme, host, port}) do
    GenServer.start_link(__MODULE__, {scheme, host, port})
  end

  def request(pid, method, path, headers, body) do
    GenServer.call(pid, {:request, method, path, headers, body})
  end

  ## Callbacks

  @impl true
  def init({scheme, host, port}) do
    case Mint.HTTP.connect(scheme, host, port) do
      {:ok, conn} ->
        state = %__MODULE__{conn: conn}
        {:ok, state}

      {:error, reason} ->
        {:stop, reason}
    end
  end

  @impl true
  def handle_call({:request, method, path, headers, body}, from, state) do
    # In both the successful case and the error case, we make sure to update the connection
    # struct in the state since the connection is an immutable data structure.
    case Mint.HTTP.request(state.conn, method, path, headers, body) do
      {:ok, conn, request_ref} ->
        state = put_in(state.conn, conn)
        # We store the caller this request belongs to and an empty map as the response.
        # The map will be filled with status code, headers, and so on.
        state = put_in(state.requests[request_ref], %{from: from, response: %{}})
        {:noreply, state}

      {:error, conn, reason} ->
        state = put_in(state.conn, conn)
        {:reply, {:error, reason}, state}
    end
  end

  @impl true
  def handle_info(message, state) do
    # We should handle the error case here as well, but we're omitting it for brevity.
    case Mint.HTTP.stream(state.conn, message) do
      :unknown ->
        _ = Logger.error(fn -> "Received unknown message: " <> inspect(message) end)
        {:noreply, state}

      {:ok, conn, responses} ->
        state = put_in(state.conn, conn)
        state = Enum.reduce(responses, state, &process_response/2)
        {:noreply, state}
    end
  end

  defp process_response({:status, request_ref, status}, state) do
    put_in(state.requests[request_ref].response[:status], status)
  end

  defp process_response({:headers, request_ref, headers}, state) do
    put_in(state.requests[request_ref].response[:headers], headers)
  end

  defp process_response({:data, request_ref, new_data}, state) do
    update_in(state.requests[request_ref].response[:data], fn data -> (data || "") <> new_data end)
  end

  # When the request is done, we use GenServer.reply/2 to reply to the caller that was
  # blocked waiting on this request.
  defp process_response({:done, request_ref}, state) do
    {%{response: response, from: from}, state} = pop_in(state.requests[request_ref])
    GenServer.reply(from, {:ok, response})
    state
  end

  # A request can also error, but we're not handling the erroneous responses for
  # brevity.
end
```
