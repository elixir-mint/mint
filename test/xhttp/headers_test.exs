defmodule XHTTP.HeadersTest do
  use ExUnit.Case, async: true
  doctest XHTTP.Headers
  import XHTTP.Headers

  @test_headers [
    {"header1", "value1"},
    {"header3", "value3-1"},
    {"header2", "value2"},
    {"HeaDer3", "value3-2"}
  ]

  test "get_header with no match" do
    assert(nil == get_header(@test_headers, "header0"))
  end

  test "get_header with case-sensitive match" do
    assert("value1" == get_header(@test_headers, "header1"))
    assert("value2" == get_header(@test_headers, "header2"))
  end

  test "get_header with case-insensitive match" do
    assert("value1" == get_header(@test_headers, "HEADER1"))
    assert("value2" == get_header(@test_headers, "hEaDeR2"))
  end

  test "get_header with multiple values" do
    assert("value3-1,value3-2" == get_header(@test_headers, "header3"))
  end

  test "get_header_values with no match" do
    assert([] == get_header_values(@test_headers, "header0"))
  end

  test "get_header_values with case-sensitive match" do
    assert(["value1"] == get_header_values(@test_headers, "header1"))
    assert(["value2"] == get_header_values(@test_headers, "header2"))
  end

  test "get_header_values with case-insensitive match" do
    assert(["value1"] == get_header_values(@test_headers, "HEADER1"))
    assert(["value2"] == get_header_values(@test_headers, "hEaDeR2"))
  end

  test "get_header_values with multiple values" do
    assert(["value3-1", "value3-2"] == get_header_values(@test_headers, "header3"))
  end

  test "put_header when value doesn't exist" do
    output = [
      {"header1", "value1"},
      {"header3", "value3-1"},
      {"header2", "value2"},
      {"HeaDer3", "value3-2"},
      {"header4", "new value"}
    ]

    assert(output == put_header(@test_headers, "header4", "new value"))
  end

  test "put_header when value exists once" do
    output = [
      {"header1", "value1"},
      {"header3", "value3-1"},
      {"HeaDer3", "value3-2"},
      {"heADer2", "new value"}
    ]

    assert(output == put_header(@test_headers, "heADer2", "new value"))
  end

  test "put_header when value exists multiple times" do
    output = [
      {"header1", "value1"},
      {"header2", "value2"},
      {"HeaDer3", "new value"}
    ]

    assert(output == put_header(@test_headers, "HeaDer3", "new value"))
  end

  test "delete_header when value doesn't exist" do
    assert(@test_headers == delete_header(@test_headers, "nope"))
  end

  test "delete_header when value exists once" do
    output = [
      {"header1", "value1"},
      {"header3", "value3-1"},
      {"HeaDer3", "value3-2"}
    ]

    assert(output == delete_header(@test_headers, "heADer2"))
  end

  test "delete_header when value exists multiple times" do
    output = [
      {"header1", "value1"},
      {"header2", "value2"}
    ]

    assert(output == delete_header(@test_headers, "HEADER3"))
  end

  test "header_names" do
    assert(["header1", "header3", "header2"] == header_names(@test_headers))
  end

  test "normalize_headers" do
    output = [
      {"header1", "value1"},
      {"header3", "value3-1,value3-2"},
      {"header2", "value2"}
    ]

    assert(output == normalize_headers(@test_headers))
  end
end
