defmodule XHTTPCore.Transport.SSLTest do
  use ExUnit.Case, async: true
  alias XHTTPCore.Transport.SSL

  describe "default ciphers" do
    test "no RSA key exchange" do
      # E.g. TLS_RSA_WITH_AES_256_GCM_SHA384 (old and new OTP variants)
      refute {:rsa, :aes_256_gcm, :aead, :sha384} in SSL.default_ciphers()
      refute {:rsa, :aes_256_gcm, :null, :sha384} in SSL.default_ciphers()
    end

    test "no AES CBC" do
      # E.g. TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA
      refute {:ecdhe_rsa, :aes_256_cbc, :sha} in SSL.default_ciphers()
    end

    test "no 3DES" do
      # E.g. TLS_ECDH_RSA_WITH_3DES_EDE_CBC_SHA
      refute {:ecdhe_rsa, :"3des_ede_cbc", :sha} in SSL.default_ciphers()
    end
  end

  # Based on https://bugs.erlang.org/browse/ERL-542
  @wildcard_san Path.expand("../../support/xhttp/wildcard_san.pem", __DIR__)

  describe "wildcard in SAN" do
    setup [:wildcard_san_cert]

    test "custom match fun for wildcard in SAN", %{cert: cert} do
      assert {:valid, _} = SSL.verify_fun(cert, :valid_peer, dns_id: 'outlook.office365.com')

      assert {:valid, _} = SSL.verify_fun(cert, :valid_peer, dns_id: 'Outlook.office365.COM')

      assert {:valid, _} =
               SSL.verify_fun(
                 cert,
                 :valid_peer,
                 dns_id: 'test.outlook.office365.com'
               )

      assert {:valid, _} =
               SSL.verify_fun(
                 cert,
                 :valid_peer,
                 uri_id: 'https://outlook.office365.com'
               )

      assert {:fail, {:bad_cert, :hostname_check_failed}} =
               SSL.verify_fun(cert, :valid_peer, dns_id: 'live.com')

      assert {:fail, {:bad_cert, :hostname_check_failed}} =
               SSL.verify_fun(cert, :valid_peer, dns_id: 'out.look.office365.com')
    end
  end

  # These certificates and the test cases that use them were taken from
  # the `public_key` library test suite in Erlang/OTP 20.3
  @cn_cert Path.expand("../../support/xhttp/pkix_verify_hostname_cn.pem", __DIR__)
  @subj_alt_name_cert Path.expand(
                        "../../support/xhttp/pkix_verify_hostname_subjAltName.pem",
                        __DIR__
                      )
  @subj_alt_name_ip_cert Path.expand(
                           "../../support/xhttp/pkix_verify_hostname_subjAltName_IP.pem",
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

  defp cn_cert(_context) do
    [cert: load_cert(@cn_cert)]
  end

  defp subj_alt_name_cert(_context) do
    [cert: load_cert(@subj_alt_name_cert)]
  end

  defp subj_alt_name_ip_cert(_context) do
    [cert: load_cert(@subj_alt_name_ip_cert)]
  end

  defp wildcard_san_cert(_context) do
    [cert: load_cert(@wildcard_san)]
  end

  defp load_cert(path) do
    [{_, binary, _} | _] = path |> File.read!() |> :public_key.pem_decode()
    :public_key.pkix_decode_cert(binary, :otp)
  end
end
