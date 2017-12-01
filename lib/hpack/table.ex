defmodule HPACK.Table do
  @moduledoc false

  defstruct [
    :max_table_size,
    table: [],
    table_size: 0
  ]

  @type t() :: %__MODULE__{
          max_table_size: non_neg_integer(),
          table: [{binary(), binary() | nil}],
          table_size: non_neg_integer()
        }

  @static_table [
    {":authority", nil},
    {":method", "GET"},
    {":method", "POST"},
    {":path", "/"},
    {":path", "/index.html"},
    {":scheme", "http"},
    {":scheme", "https"},
    {":status", "200"},
    {":status", "204"},
    {":status", "206"},
    {":status", "304"},
    {":status", "400"},
    {":status", "404"},
    {":status", "500"},
    {"accept-charset", nil},
    {"accept-encoding", "gzip, deflate"},
    {"accept-language", nil},
    {"accept-ranges", nil},
    {"accept", nil},
    {"access-control-allow-origin", nil},
    {"age", nil},
    {"allow", nil},
    {"authorization", nil},
    {"cache-control", nil},
    {"content-disposition", nil},
    {"content-encoding", nil},
    {"content-language", nil},
    {"content-length", nil},
    {"content-location", nil},
    {"content-range", nil},
    {"content-type", nil},
    {"cookie", nil},
    {"date", nil},
    {"etag", nil},
    {"expect", nil},
    {"expires", nil},
    {"from", nil},
    {"host", nil},
    {"if-match", nil},
    {"if-modified-since", nil},
    {"if-none-match", nil},
    {"if-range", nil},
    {"if-unmodified-since", nil},
    {"last-modified", nil},
    {"link", nil},
    {"location", nil},
    {"max-forwards", nil},
    {"proxy-authenticate", nil},
    {"proxy-authorization", nil},
    {"range", nil},
    {"referer", nil},
    {"refresh", nil},
    {"retry-after", nil},
    {"server", nil},
    {"set-cookie", nil},
    {"strict-transport-security", nil},
    {"transfer-encoding", nil},
    {"user-agent", nil},
    {"vary", nil},
    {"via", nil},
    {"www-authenticate", nil}
  ]

  @static_table_size length(@static_table)
  @dynamic_table_start @static_table_size + 1

  def static_table() do
    @static_table
  end

  @doc "TODO"
  def new(max_table_size) do
    %__MODULE__{max_table_size: max_table_size}
  end

  @doc "TODO"
  def add(%__MODULE__{} = table, {name, value}) do
    entry_size = entry_size(name, value)

    cond do
      # An attempt to add an entry larger than the maximum size causes the table to be emptied of
      # all existing entries and results in an empty table.
      entry_size > table.max_table_size ->
        %{table | table: [], table_size: 0}

      table.table_size + entry_size > table.max_table_size ->
        table
        |> shrink(table.max_table_size - entry_size)
        |> add_header(name, value, entry_size)

      true ->
        add_header(table, name, value, entry_size)
    end
  end

  defp add_header(%__MODULE__{} = table, name, value, entry_size) do
    %{
      table
      | table: [{name, value} | table.table],
        table_size: table.table_size + entry_size
    }
  end

  @doc "TODO"
  @spec lookup_by_index(t(), pos_integer()) :: {:ok, {binary(), binary() | nil}} | :error
  def lookup_by_index(table, index)

  # Static table
  for {header, index} <- Enum.with_index(@static_table, 1) do
    def lookup_by_index(%__MODULE__{}, unquote(index)), do: {:ok, unquote(header)}
  end

  def lookup_by_index(%__MODULE__{table: table}, index)
      when index in @dynamic_table_start..length(table) do
    {:ok, Enum.at(table, index - @dynamic_table_start)}
  end

  def lookup_by_index(%__MODULE__{}, _index) do
    :error
  end

  @doc "TODO"
  @spec lookup_by_header(t(), {binary(), binary() | nil}) ::
          {:full, pos_integer()} | {:name, pos_integer()} | :not_found
  def lookup_by_header(table, header)

  def lookup_by_header(%__MODULE__{table: table}, {name, value}) do
    case static_lookup_by_header({name, value}) do
      {:full, _index} = result ->
        result

      {:name, index} ->
        # Check if we get full match in the dynamic tabble
        case dynamic_lookup_by_header(table, name, value, @dynamic_table_start, nil) do
          {:full, _index} = result -> result
          _other -> {:name, index}
        end

      :not_found ->
        dynamic_lookup_by_header(table, name, value, @dynamic_table_start, nil)
    end
  end

  for {{name, value}, index} <- Enum.with_index(@static_table, 1) do
    if value != nil do
      defp static_lookup_by_header({unquote(name), unquote(value)}) do
        {:full, unquote(index)}
      end
    end
  end

  static_table_names =
    @static_table
    |> Enum.map(&elem(&1, 0))
    |> Enum.with_index(1)
    |> Enum.uniq_by(&elem(&1, 0))

  for {name, index} <- static_table_names do
    defp static_lookup_by_header({unquote(name), _value}) do
      {:name, unquote(index)}
    end
  end

  defp static_lookup_by_header(_other) do
    :not_found
  end

  defp dynamic_lookup_by_header([{name, value} | _rest], name, value, index, _best_index_so_far) do
    {:full, index}
  end

  defp dynamic_lookup_by_header([{name, _} | rest], name, value, index, _best_index_so_far) do
    dynamic_lookup_by_header(rest, name, value, index + 1, index)
  end

  defp dynamic_lookup_by_header([_other | rest], name, value, index, best_index_so_far) do
    dynamic_lookup_by_header(rest, name, value, index + 1, best_index_so_far)
  end

  defp dynamic_lookup_by_header([], _name, _value, _index, best_index_so_far) do
    if best_index_so_far do
      {:name, best_index_so_far}
    else
      :not_found
    end
  end

  @doc "TODO"
  def shrink(%__MODULE__{} = table, new_size) do
    {new_table_reversed, new_size} =
      evict_towards_size(Enum.reverse(table.table), table.table_size, new_size)

    %{table | table: Enum.reverse(new_table_reversed), table_size: new_size}
  end

  defp evict_towards_size([{name, value} | rest], size, max_target_size) do
    new_size = size - entry_size(name, value)

    if new_size <= max_target_size do
      {rest, size}
    else
      evict_towards_size(rest, new_size, max_target_size)
    end
  end

  defp evict_towards_size([], 0, _max_target_size) do
    {[], 0}
  end

  defp entry_size(name, value) do
    byte_size(name) + byte_size(value) + 32
  end
end
