defmodule XHTTP2.HPACK.Table do
  defstruct [
    :max_table_size,
    dynamic_table: {%{}, 0}
  ]

  @type header() :: {binary(), binary()}
  @type t() :: %__MODULE__{
          max_table_size: non_neg_integer(),
          dynamic_table: {%{optional(non_neg_integer()) => header()}, non_neg_integer()}
        }

  @static_table %{
    1 => {":authority", nil},
    2 => {":method", "GET"},
    3 => {":method", "POST"},
    4 => {":path", "/"},
    5 => {":path", "/index.html"},
    6 => {":scheme", "http"},
    7 => {":scheme", "https"},
    8 => {":status", "200"},
    9 => {":status", "204"},
    10 => {":status", "206"},
    11 => {":status", "304"},
    12 => {":status", "400"},
    13 => {":status", "404"},
    14 => {":status", "500"},
    15 => {"accept-charset", nil},
    16 => {"accept-encoding", "gzip, deflate"},
    17 => {"accept-language", nil},
    18 => {"accept-ranges", nil},
    19 => {"accept", nil},
    20 => {"access-control-allow-origin", nil},
    21 => {"age", nil},
    22 => {"allow", nil},
    23 => {"authorization", nil},
    24 => {"cache-control", nil},
    25 => {"content-disposition", nil},
    26 => {"content-encoding", nil},
    27 => {"content-language", nil},
    28 => {"content-length", nil},
    29 => {"content-location", nil},
    30 => {"content-range", nil},
    31 => {"content-type", nil},
    32 => {"cookie", nil},
    33 => {"date", nil},
    34 => {"etag", nil},
    35 => {"expect", nil},
    36 => {"expires", nil},
    37 => {"from", nil},
    38 => {"host", nil},
    39 => {"if-match", nil},
    40 => {"if-modified-since", nil},
    41 => {"if-none-match", nil},
    42 => {"if-range", nil},
    43 => {"if-unmodified-since", nil},
    44 => {"last-modified", nil},
    45 => {"link", nil},
    46 => {"location", nil},
    47 => {"max-forwards", nil},
    48 => {"proxy-authenticate", nil},
    49 => {"proxy-authorization", nil},
    50 => {"range", nil},
    51 => {"referer", nil},
    52 => {"refresh", nil},
    53 => {"retry-after", nil},
    54 => {"server", nil},
    55 => {"set-cookie", nil},
    56 => {"strict-transport-security", nil},
    57 => {"transfer-encoding", nil},
    58 => {"user-agent", nil},
    59 => {"vary", nil},
    60 => {"via", nil},
    61 => {"www-authenticate", nil}
  }

  @static_table_size map_size(@static_table)

  def static_table() do
    @static_table
  end

  @spec new(non_neg_integer()) :: t()
  def new(max_table_size) do
    %__MODULE__{max_table_size: max_table_size}
  end

  @spec add(t(), header()) :: t()
  def add(%__MODULE__{} = table, {_name, _value} = header) do
    %__MODULE__{
      dynamic_table: {_, dynamic_table_size} = dynamic_table,
      max_table_size: max_table_size
    } = table

    entry_size = entry_size(header)

    cond do
      # An attempt to add an entry larger than the maximum size causes the table to be emptied of
      # all existing entries and results in an empty table.
      entry_size > max_table_size ->
        %{table | dynamic_table: {%{}, 0}}

      dynamic_table_size + entry_size > max_table_size ->
        dynamic_table =
          dynamic_table
          |> evict_towards_size(max_table_size - entry_size)
          |> append_to_dynamic_table(header)

        %{table | dynamic_table: dynamic_table}

      true ->
        dynamic_table = append_to_dynamic_table(dynamic_table, header)
        %{table | dynamic_table: dynamic_table}
    end
  end

  @spec fetch(t(), pos_integer()) :: header()
  def fetch(table, index)

  def fetch(%__MODULE__{}, index) when index in 1..@static_table_size do
    Map.fetch(@static_table, index)
  end

  def fetch(%__MODULE__{dynamic_table: {table, size}}, index)
      when (index - @static_table_size) in 1..size do
    Map.fetch(table, index - @static_table_size)
  end

  def fetch(%__MODULE__{}, _index) do
    :error
  end

  @spec shrink(t(), non_neg_integer()) :: t()
  def shrink(%__MODULE__{dynamic_table: dynamic_table} = table, new_size) do
    new_dynamic_table = evict_towards_size(dynamic_table, new_size)
    %{table | dynamic_table: new_dynamic_table, max_table_size: new_size}
  end

  defp append_to_dynamic_table({table, table_size}, header) do
    next_index = map_size(table) + 1
    {Map.put(table, next_index, header), table_size + entry_size(header)}
  end

  defp evict_towards_size({table, size}, max_target_size) do
    last_index = map_size(table)
    {last_entry, table} = Map.pop(table, last_index)
    new_size = size - entry_size(last_entry)

    if new_size <= max_target_size do
      {table, new_size}
    else
      evict_towards_size({table, new_size}, max_target_size)
    end
  end

  defp entry_size({name, value}) do
    byte_size(name) + byte_size(value) + 32
  end
end
