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

    if System.otp_release() >= "26" do
      test "with an SSL reason" do
        # This error reason type is specific to OTP 26+.
        error = %TransportError{reason: {:tls_alert, {:unknown_ca, ~c"unknown ca"}}}
        assert Exception.message(error) == "unknown ca"
      end
    end

    test "with a POSIX reason" do
      error = %TransportError{reason: :econnrefused}
      assert Exception.message(error) == "connection refused"
    end

    test "with :bad_alpn_protocol sa the reason" do
      error = %TransportError{reason: {:bad_alpn_protocol, :h3}}

      assert Exception.message(error) ==
               ~s(bad ALPN protocol :h3, supported protocols are "http/1.1" and "h2")
    end

    test "with an unknown reason" do
      error = %TransportError{reason: :unknown}
      assert Exception.message(error) == ":unknown"
    end
  end
end
