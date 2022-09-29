require 'openssl'
require 'open-uri'

class MkChain
  class NoChainFoundException < Exception; end

  def self.store
    @@store ||= begin
      # Download the Mozilla CA certs
      cacerts = URI('https://curl.se/ca/cacert.pem').open()
      if cacerts.is_a?(StringIO)
        tempfile = Tempfile.new("open-uri", binmode: true)
        IO.copy_stream(cacerts, tempfile.path)
        cacerts = tempfile
        OpenURI::Meta.init cacerts, stringio
      end

      # Load them into a new store
      OpenSSL::X509::Store.new.add_file(cacerts.path)
    end
  end

  def self.chain(cert_str)
    chain = []
    ca = cert = OpenSSL::X509::Certificate.new(cert_str)

    loop do
      url = ca.extensions.select { |ext| ext.oid == 'authorityInfoAccess' }
        .first.value.match(%r{^CA Issuers - URI:(https?://.+)$})[1] rescue break

      ca = OpenSSL::X509::Certificate.new(URI.open(url).read) rescue break
      store.add_cert(ca)
      if store.verify(cert) && store.chain.length > 1
        chain = store.chain[1..].map(&:to_pem)
        break
      end
      chain << ca.to_pem
    end

    raise NoChainFoundException, 'No intermediate chain found' if chain.empty?

    # the last cert will be the root cert, which doesn't belong in the chain
    chain[0..-1].join
  end
end
