require_relative "../enclave"

require "uri"
require "json"
require "ipaddr"
require "resolv"
require "net/http"

class Enclave
  # Optional, batteries-included network tool for the sandbox. SSRF is the
  # classic pivot the moment you give untrusted code HTTP — it can borrow your
  # server's network position to reach internal services or the cloud metadata
  # endpoint — and it is easy to get wrong, so this bundles the defenses.
  #
  # Expose it like any tool object. Only the HTTP verb methods are public, so
  # nothing internal (budgets, validators, DNS) leaks into the sandbox:
  #
  #   http = Enclave::HttpTool.new(allow: %w[api.example.com *.githubusercontent.com])
  #   enclave.expose(http)
  #   enclave.eval('get("https://api.example.com/status")["body"]')
  #
  # Defenses, in order, per request:
  #   1. budget    — request count + wall-clock across the tool's lifetime; the
  #                  enclave timeout never counts host time, so the tool meters
  #                  itself
  #   2. URL       — http/https only, no userinfo, no IP-literal host, port
  #                  allowlist, CR/LF/NUL rejection
  #   3. allowlist — hostname label-suffix match ("*.x.y"), never substring;
  #                  allow: :any skips ONLY the allowlist (the SSRF floor holds)
  #   4. headers   — reserved headers (Host/Content-Length/Transfer-Encoding/
  #                  Connection) blocked, token-charset names, no CR/LF;
  #                  Authorization is allowed — you set your own credentials
  #   5. DNS + IP  — resolve once, reject any resolved private/link-local/
  #                  metadata IP, then pin the connection to the vetted IP so a
  #                  rebinding resolver can't swap it after the check
  #   6. response  — body capped while streaming; redirects are returned to the
  #                  sandbox, never auto-followed
  #
  # Hash/Array bodies are JSON-encoded host-side and JSON responses are parsed
  # host-side, since the sandbox build carries no JSON.
  class HttpTool
    class DeniedError < StandardError; end

    RESERVED_HEADERS = %w[host content-length transfer-encoding connection].freeze
    ALLOWED_METHODS  = %w[GET POST PUT PATCH DELETE HEAD].freeze
    HEADER_NAME      = /\A[!#$%&'*+\-.^_`|~0-9A-Za-z]+\z/

    # Ranges that must never be reachable through the tool: loopback, private,
    # link-local (incl. 169.254.169.254 cloud metadata), CGNAT, IPv6 ULA/LL, and
    # IPv4-mapped IPv6.
    PRIVATE_RANGES = %w[
      0.0.0.0/8 10.0.0.0/8 100.64.0.0/10 127.0.0.0/8 169.254.0.0/16
      172.16.0.0/12 192.0.0.0/24 192.168.0.0/16 198.18.0.0/15
      ::1/128 fc00::/7 fe80::/10 ::ffff:0:0/96
    ].map { |cidr| IPAddr.new(cidr) }.freeze

    # allow: an array of host patterns (exact "api.x.com" or label-wildcard
    # "*.x.com"), or :any to skip the allowlist while keeping the SSRF floor.
    # on_request: optional host-side callable, ->(info_hash) — audit/metering.
    # transport: injectable for tests; defaults to the real DNS-pinning transport.
    def initialize(allow:, max_requests: 20, request_timeout: 5,
                   total_time_budget: 15, max_response_bytes: 1_000_000,
                   allowed_ports: [80, 443], on_request: nil, transport: nil)
      @allow_any = (allow == :any)
      @patterns = @allow_any ? [] : Array(allow).map { |domain| normalize_pattern(domain) }
      @max_requests = max_requests
      @total_time_budget = total_time_budget
      @allowed_ports = allowed_ports
      @on_request = on_request
      @transport = transport ||
        NetHttpTransport.new(request_timeout: request_timeout, max_response_bytes: max_response_bytes)
      reset_budget!
    end

    # The single primitive. Returns a Hash:
    #   { "status" => Integer, "headers" => {lowercased => String},
    #     "body" => parsed-JSON-or-String, "json" => Boolean }
    def request(method, url, headers = {}, body = nil)
      spend!
      method = method.to_s.upcase
      deny!("method not allowed: #{method}") unless ALLOWED_METHODS.include?(method)

      uri = validate_url!(url.to_s)
      clean_headers = validate_headers!(headers || {})
      body_string = encode_body(body, clean_headers)

      response = @transport.perform(method, uri, clean_headers, body_string,
                                    ip_validator: method(:validate_resolved_ips!))
      @on_request&.call(method: method, host: uri.host, path: uri.path,
                        status: response[:status], bytes: response[:body].to_s.bytesize)
      decode_response(response)
    end

    # Verb sugar for the sandbox.
    def get(url, headers = {})    = request("GET", url, headers, nil)
    def head(url, headers = {})   = request("HEAD", url, headers, nil)
    def delete(url, headers = {}) = request("DELETE", url, headers, nil)
    def post(url, body = nil, headers = {})  = request("POST", url, headers, body)
    def put(url, body = nil, headers = {})   = request("PUT", url, headers, body)
    def patch(url, body = nil, headers = {}) = request("PATCH", url, headers, body)

    private

    def reset_budget!
      @requests = 0
      @started_at = nil
    end

    def deny!(reason)
      raise DeniedError, "http denied: #{reason}"
    end

    def spend!
      @requests += 1
      deny!("request budget exceeded (#{@max_requests} per tool)") if @requests > @max_requests
      now = Process.clock_gettime(Process::CLOCK_MONOTONIC)
      @started_at ||= now
      if now - @started_at > @total_time_budget
        deny!("network time budget exceeded (#{@total_time_budget}s per tool)")
      end
    end

    # Called back by the transport (which owns DNS) once it has resolved the
    # host. Private, but reachable via method(:...) — never exposed to the sandbox.
    def validate_resolved_ips!(host, addresses)
      deny!("DNS resolution failed for #{host}") if addresses.empty?
      addresses.each do |address|
        ip = IPAddr.new(address)
        if PRIVATE_RANGES.any? { |range| range.include?(ip) }
          deny!("#{host} resolves to a private or link-local address")
        end
      end
    end

    def validate_url!(url)
      deny!("control characters in URL") if url.match?(/[\r\n\0]/)
      uri =
        begin
          URI.parse(url)
        rescue URI::InvalidURIError
          deny!("unparseable URL")
        end
      deny!("scheme must be http or https") unless %w[http https].include?(uri.scheme)
      deny!("missing host") if uri.host.nil? || uri.host.empty?
      deny!("userinfo not allowed in URL") if uri.userinfo
      deny!("port #{uri.port} not allowed") unless @allowed_ports.include?(uri.port)

      host = normalize_host(uri.host)
      deny!("IP-literal hosts not allowed") if ip_literal?(host)
      deny!("#{host} is not in the allowlist") unless allowed_host?(host)
      uri
    end

    def validate_headers!(headers)
      deny!("headers must be a Hash") unless headers.is_a?(Hash)
      headers.each_with_object({}) do |(name, value), clean|
        name = name.to_s
        value = value.to_s
        deny!("invalid header name: #{name.inspect}") unless name.match?(HEADER_NAME)
        deny!("reserved header: #{name}") if RESERVED_HEADERS.include?(name.downcase)
        deny!("control characters in header value") if value.match?(/[\r\n\0]/)
        clean[name] = value
      end
    end

    def encode_body(body, headers)
      case body
      when nil then nil
      when Hash, Array
        headers["Content-Type"] ||= "application/json"
        JSON.generate(body)
      when String then body
      else deny!("unsupported body type: #{body.class}")
      end
    end

    def decode_response(response)
      content_type = response[:headers]["content-type"].to_s
      body = response[:body].to_s
      json = content_type.include?("json") && !body.empty?
      parsed = json ? (JSON.parse(body) rescue (json = false; body)) : body
      {
        "status"  => response[:status],
        "headers" => response[:headers],
        "body"    => parsed,
        "json"    => json
      }
    end

    def normalize_pattern(domain)
      pattern = domain.to_s.downcase.strip.chomp(".")
      raise ArgumentError, "empty allowlist entry" if pattern.empty?
      pattern
    end

    def normalize_host(host)
      host.downcase.chomp(".")
    end

    def ip_literal?(host)
      IPAddr.new(host.delete_prefix("[").delete_suffix("]"))
      true
    rescue IPAddr::InvalidAddressError
      false
    end

    def allowed_host?(host)
      return true if @allow_any
      host_labels = host.split(".")
      @patterns.any? do |pattern|
        if pattern.start_with?("*.")
          suffix = pattern.delete_prefix("*.").split(".")
          host_labels.length > suffix.length && host_labels.last(suffix.length) == suffix
        else
          host == pattern
        end
      end
    end

    # Production transport: resolve once, validate every IP, pin the connection
    # to the vetted address (Host header + SNI stay the hostname).
    class NetHttpTransport
      def initialize(request_timeout:, max_response_bytes:)
        @request_timeout = request_timeout
        @max_response_bytes = max_response_bytes
      end

      def perform(method, uri, headers, body, ip_validator:)
        addresses = Resolv.getaddresses(uri.host)
        ip_validator.call(uri.host, addresses)

        http = Net::HTTP.new(uri.host, uri.port)
        http.ipaddr = addresses.first # connection goes to the vetted IP; Host/SNI stay uri.host
        http.use_ssl = (uri.scheme == "https")
        http.open_timeout = @request_timeout
        http.read_timeout = @request_timeout

        request = Net::HTTP.const_get(method.capitalize).new(uri.request_uri)
        headers.each { |name, value| request[name] = value }
        request.body = body if body

        http.start do |session|
          session.request(request) do |response|
            buffer = +""
            response.read_body do |chunk|
              buffer << chunk
              if buffer.bytesize > @max_response_bytes
                raise DeniedError, "http denied: response exceeds #{@max_response_bytes} bytes"
              end
            end
            return {
              status:  response.code.to_i,
              headers: response.to_hash.transform_keys(&:downcase).transform_values(&:first),
              body:    buffer
            }
          end
        end
      end
    end
  end
end
