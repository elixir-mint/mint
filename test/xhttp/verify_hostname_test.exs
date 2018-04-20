defmodule XHTTP.VerifyHostnameTest do
  use ExUnit.Case, async: true

  # These certificates and the test cases that use them were taken from
  # the `public_key` library test suite in Erlang/OTP 20.3
  @cn_cert Path.expand("../support/xhttp/pkix_verify_hostname_cn.pem", __DIR__)
  @subj_alt_name_cert Path.expand(
                        "../support/xhttp/pkix_verify_hostname_subjAltName.pem",
                        __DIR__
                      )
  @subj_alt_name_ip_cert Path.expand(
                           "../support/xhttp/pkix_verify_hostname_subjAltName_IP.pem",
                           __DIR__
                         )

  describe "verify_hostname (CN)" do
    setup [:cn_cert]

    test "OTP public_key test cases", %{cert: cert} do
      # Check that 1) only CNs are checked,
      #            2) an empty label does not match a wildcard and
      #            3) a wildcard does not match more than one label
      refute :xhttp_shims.pkix_verify_hostname(
               cert,
               dns_id: 'erlang.org',
               dns_id: 'foo.EXAMPLE.com',
               dns_id: 'b.a.foo.EXAMPLE.com'
             )

      # Check that a hostname is extracted from a https-uri and used for checking:
      assert :xhttp_shims.pkix_verify_hostname(cert, uri_id: 'HTTPS://EXAMPLE.com')

      # Check wildcard matching one label:
      assert :xhttp_shims.pkix_verify_hostname(cert, dns_id: 'a.foo.EXAMPLE.com')

      # Check wildcard with surrounding chars matches one label:
      assert :xhttp_shims.pkix_verify_hostname(cert, dns_id: 'accb.bar.EXAMPLE.com')

      # Check that a wildcard with surrounding chars matches an empty string:
      assert :xhttp_shims.pkix_verify_hostname(cert, uri_id: 'https://ab.bar.EXAMPLE.com')
    end
  end

  describe "verify_hostname (subj_alt_name)" do
    setup [:subj_alt_name_cert]

    test "OTP public_key test cases", %{cert: cert} do
      # Check that neither a uri nor dns hostname matches a CN if subjAltName is present:
      refute :xhttp_shims.pkix_verify_hostname(
               cert,
               uri_id: 'https://example.com',
               dns_id: 'example.com'
             )

      # Check that a uri_id matches a URI subjAltName:
      assert :xhttp_shims.pkix_verify_hostname(cert, uri_id: 'https://wws.example.org')

      # Check that a dns_id does not match a URI subjAltName:
      refute :xhttp_shims.pkix_verify_hostname(
               cert,
               dns_id: 'www.example.org',
               dns_id: 'wws.example.org'
             )

      # Check that a dns_id matches a DNS subjAltName:
      assert :xhttp_shims.pkix_verify_hostname(cert, dns_id: 'kb.example.org')
    end
  end

  describe "verify_hostname (subj_alt_name_ip)" do
    setup [:subj_alt_name_ip_cert]

    test "OTP public_key test cases", %{cert: cert} do
      refute :xhttp_shims.pkix_verify_hostname(cert, uri_id: 'https://1.2.3.4')
      assert :xhttp_shims.pkix_verify_hostname(cert, uri_id: 'https://10.11.12.13')
      assert :xhttp_shims.pkix_verify_hostname(cert, dns_id: '1.2.3.4')
      assert :xhttp_shims.pkix_verify_hostname(cert, dns_id: "1.2.3.4")
      refute :xhttp_shims.pkix_verify_hostname(cert, dns_id: '10.67.16.75')
      assert :xhttp_shims.pkix_verify_hostname(cert, ip: 'aBcD:ef:0::0:1')
      assert :xhttp_shims.pkix_verify_hostname(cert, ip: {0xABCD, 0xEF, 0, 0, 0, 0, 0, 1})
      assert :xhttp_shims.pkix_verify_hostname(cert, ip: '10.67.16.75')
      assert :xhttp_shims.pkix_verify_hostname(cert, ip: "10.67.16.75")
      assert :xhttp_shims.pkix_verify_hostname(cert, ip: {10, 67, 16, 75})
      refute :xhttp_shims.pkix_verify_hostname(cert, ip: {1, 2, 3, 4})
      refute :xhttp_shims.pkix_verify_hostname(cert, ip: {10, 11, 12, 13})
    end
  end

  defp cn_cert(_) do
    [cert: load_cert(@cn_cert)]
  end

  defp subj_alt_name_cert(_) do
    [cert: load_cert(@subj_alt_name_cert)]
  end

  defp subj_alt_name_ip_cert(_) do
    [cert: load_cert(@subj_alt_name_ip_cert)]
  end

  defp load_cert(path) do
    path
    |> File.read!()
    |> :public_key.pem_decode()
    |> hd()
    |> elem(1)
    |> :public_key.pkix_decode_cert(:otp)
  end
end
