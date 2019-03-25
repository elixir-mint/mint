defmodule Mint.TransportErrorTest do
  use ExUnit.Case, async: true

  alias Mint.TransportError

  describe "Exception.message/1" do
    test "with one of our reasons" do
      error = %TransportError{reason: :closed}
      assert Exception.message(error) == "socket closed"

      error = %TransportError{reason: :timeout}
      assert Exception.message(error) == "timeout"

      error = %TransportError{reason: :protocol_not_negotiated}
      assert Exception.message(error) == "ALPN protocol not negotiated"
    end

    test "with an SSL reason" do
      # OTP 21.3 changes the reasons used in :ssl.error_alert/0. For simplicity let's
      # just accept both ways.
      error = %TransportError{reason: {:tls_alert, 'unknown ca'}}
      assert Exception.message(error) in ["TLS Alert: unknown ca", "{:tls_alert, 'unknown ca'}"]
    end

    test "with a POSIX reason" do
      error = %TransportError{reason: :econnrefused}
      assert Exception.message(error) == "connection refused"
    end

    test "with an unknown reason" do
      error = %TransportError{reason: :unknown}
      assert Exception.message(error) == ":unknown"
    end
  end
end
