require "enclave/http_tool"
require "socket"

# Records requests, invokes the IP validator with controlled addresses, and
# returns a canned response — so the policy layer can be tested without network.
class FakeTransport
  attr_reader :calls

  def initialize(resolve_to: ["93.184.216.34"],
                 response: { status: 200, headers: { "content-type" => "application/json" }, body: '{"ok":true}' })
    @resolve_to = resolve_to
    @response = response
    @calls = []
  end

  def perform(method, uri, headers, body, ip_validator:)
    @calls << { method: method, host: uri.host, path: uri.request_uri, headers: headers, body: body }
    ip_validator.call(uri.host, @resolve_to)
    @response
  end
end

RSpec.describe Enclave::HttpTool do
  Denied = Enclave::HttpTool::DeniedError

  def tool(allow: %w[api.example.com *.githubusercontent.com], **transport_opts)
    described_class.new(allow: allow, transport: FakeTransport.new(**transport_opts))
  end

  describe "URL rules" do
    it "allows an allowlisted host and returns a parsed JSON body" do
      r = tool.get("https://api.example.com/x")
      expect(r["status"]).to eq(200)
      expect(r["body"]).to eq({ "ok" => true })
      expect(r["json"]).to be true
    end

    it "denies a non-allowlisted host" do
      expect { tool.get("https://evil.com/") }.to raise_error(Denied, /not in the allowlist/)
    end

    it "denies a non-http(s) scheme" do
      expect { tool.get("ftp://api.example.com/") }.to raise_error(Denied, /scheme/)
    end

    it "denies userinfo in the URL" do
      expect { tool.get("https://user:pw@api.example.com/") }.to raise_error(Denied, /userinfo/)
    end

    it "denies an IP-literal host" do
      expect { tool(allow: :any).get("https://93.184.216.34/") }.to raise_error(Denied, /IP-literal/)
    end

    it "denies a port outside the allowlist" do
      expect { tool.get("https://api.example.com:8080/") }.to raise_error(Denied, /port/)
    end

    it "denies control characters in the URL" do
      expect { tool.get("https://api.example.com/\r\nHost: evil") }.to raise_error(Denied, /control characters/)
    end
  end

  describe "allowlist matching" do
    it "matches an exact host" do
      expect(tool.get("https://api.example.com/")["status"]).to eq(200)
    end

    it "matches a label wildcard by suffix" do
      expect(tool.get("https://raw.githubusercontent.com/a")["status"]).to eq(200)
    end

    it "does not match by substring" do
      expect { tool.get("https://api.example.com.evil.com/") }.to raise_error(Denied)
    end

    it "does not let a wildcard match the bare domain" do
      expect { tool(allow: %w[*.example.com]).get("https://example.com/") }.to raise_error(Denied)
    end

    it "allow: :any skips the allowlist but keeps the SSRF floor" do
      expect(tool(allow: :any).get("https://anything.example.org/")["status"]).to eq(200)
      expect { tool(allow: :any, resolve_to: ["10.0.0.1"]).get("https://anything.example.org/") }
        .to raise_error(Denied, /private/)
    end

    it 'accepts the ["ANY"] sentinel as an alias for :any (host-policy compat)' do
      expect(tool(allow: ["ANY"]).get("https://anything.example.org/")["status"]).to eq(200)
      expect { tool(allow: ["ANY"], resolve_to: ["169.254.169.254"]).get("https://x.example.org/") }
        .to raise_error(Denied, /private/)
    end
  end

  describe "reset_budget!" do
    it "is public and resets the per-tool request budget for host reuse" do
      t = described_class.new(allow: %w[api.example.com], max_requests: 2, transport: FakeTransport.new)
      2.times { t.get("https://api.example.com/") }
      expect { t.get("https://api.example.com/") }.to raise_error(Denied, /request budget/)
      t.reset_budget!
      expect(t.get("https://api.example.com/")["status"]).to eq(200)
    end
  end

  describe "header rules" do
    it "denies reserved headers" do
      expect { tool.get("https://api.example.com/", { "Host" => "evil" }) }.to raise_error(Denied, /reserved/)
    end

    it "denies invalid header names" do
      expect { tool.get("https://api.example.com/", { "Bad Name" => "x" }) }.to raise_error(Denied, /header name/)
    end

    it "denies control characters in header values" do
      expect { tool.get("https://api.example.com/", { "X" => "a\r\nb" }) }.to raise_error(Denied, /control characters/)
    end

    it "allows Authorization" do
      expect(tool.get("https://api.example.com/", { "Authorization" => "Bearer t" })["status"]).to eq(200)
    end
  end

  describe "DNS and IP pinning" do
    %w[10.0.0.5 127.0.0.1 169.254.169.254 172.16.0.1 192.168.1.1 ::1 fe80::1].each do |ip|
      it "denies a host that resolves to #{ip}" do
        expect { tool(resolve_to: [ip]).get("https://api.example.com/") }
          .to raise_error(Denied, /private or link-local/)
      end
    end

    it "denies when DNS returns no addresses" do
      expect { tool(resolve_to: []).get("https://api.example.com/") }.to raise_error(Denied, /DNS/)
    end

    it "denies if ANY resolved address is private (rebinding defense)" do
      expect { tool(resolve_to: ["93.184.216.34", "10.0.0.1"]).get("https://api.example.com/") }
        .to raise_error(Denied, /private/)
    end
  end

  describe "budgets" do
    it "denies past the request count budget" do
      t = described_class.new(allow: %w[api.example.com], max_requests: 2, transport: FakeTransport.new)
      2.times { t.get("https://api.example.com/") }
      expect { t.get("https://api.example.com/") }.to raise_error(Denied, /request budget/)
    end
  end

  describe "body and response" do
    it "JSON-encodes a Hash body and sets the content type" do
      ft = FakeTransport.new
      described_class.new(allow: %w[api.example.com], transport: ft).post("https://api.example.com/", { a: 1 })
      expect(ft.calls.last[:body]).to eq('{"a":1}')
      expect(ft.calls.last[:headers]["Content-Type"]).to eq("application/json")
    end

    it "passes a String body through unchanged" do
      ft = FakeTransport.new
      described_class.new(allow: %w[api.example.com], transport: ft).post("https://api.example.com/", "raw")
      expect(ft.calls.last[:body]).to eq("raw")
    end

    it "returns a non-JSON body as a String" do
      ft = FakeTransport.new(response: { status: 200, headers: { "content-type" => "text/plain" }, body: "hello" })
      r = described_class.new(allow: %w[api.example.com], transport: ft).get("https://api.example.com/")
      expect(r["body"]).to eq("hello")
      expect(r["json"]).to be false
    end
  end

  describe "on_request audit callback" do
    it "fires with request info after a successful call" do
      seen = []
      t = described_class.new(allow: %w[api.example.com], transport: FakeTransport.new,
                              on_request: ->(info) { seen << info })
      t.get("https://api.example.com/path")
      expect(seen.size).to eq(1)
      expect(seen.first).to include(host: "api.example.com", status: 200)
    end
  end

  describe "exposing into an enclave" do
    let(:enclave) { Enclave.new(timeout: 5) }
    after { enclave.close unless enclave.closed? }

    it "exposes only the HTTP verb methods, not internals" do
      enclave.expose(described_class.new(allow: %w[api.example.com], transport: FakeTransport.new))
      expect(enclave.exposed_functions).to match_array(%i[request get head delete post put patch])
    end

    it "lets sandboxed code make an allowed request" do
      enclave.expose(described_class.new(allow: %w[api.example.com], transport: FakeTransport.new))
      expect(enclave.eval('get("https://api.example.com/x")["status"]').value).to eq("200")
    end

    it "does not let sandboxed code reach reset_budget! though it is public to the host" do
      http = described_class.new(allow: %w[api.example.com], transport: FakeTransport.new)
      expect(http.respond_to?(:reset_budget!)).to be true # host can call it directly
      enclave.expose(http)
      expect(enclave.exposed_functions).not_to include(:reset_budget!)
      expect(enclave.eval("reset_budget!").error?).to be true # but the sandbox cannot
    end

    it "refuses to expose reset_budget! even under an explicit only:" do
      http = described_class.new(allow: %w[api.example.com], transport: FakeTransport.new)
      expect { enclave.expose(http, only: %i[reset_budget!]) }.to raise_error(ArgumentError)
    end

    it "surfaces a denial to sandboxed code as an error" do
      enclave.expose(described_class.new(allow: %w[api.example.com], transport: FakeTransport.new))
      result = enclave.eval('get("https://evil.com/")')
      expect(result.error?).to be true
      expect(result.error).to include("http denied")
    end
  end

  # The real transport, exercised against a local server with a no-op IP
  # validator (127.0.0.1 is otherwise correctly denied by the private-range
  # check — that path is covered above at the tool level).
  describe Enclave::HttpTool::NetHttpTransport do
    def with_server(body:, content_type: "text/plain")
      server = TCPServer.new("127.0.0.1", 0)
      port = server.addr[1]
      thread = Thread.new do
        loop do
          client = server.accept
          client.gets("\r\n\r\n")
          client.write("HTTP/1.1 200 OK\r\nContent-Type: #{content_type}\r\n" \
                       "Content-Length: #{body.bytesize}\r\nConnection: close\r\n\r\n")
          client.write(body)
          client.close
        rescue IOError, Errno::EPIPE
          # client went away; keep serving
        end
      end
      yield port
    ensure
      thread&.kill
      server&.close
    end

    let(:noop_validator) { ->(_host, _addrs) {} }

    it "performs a real request and returns status/headers/body" do
      with_server(body: "hi there") do |port|
        transport = described_class.new(request_timeout: 5, max_response_bytes: 1_000_000)
        uri = URI.parse("http://127.0.0.1:#{port}/x")
        resp = transport.perform("GET", uri, {}, nil, ip_validator: noop_validator)
        expect(resp[:status]).to eq(200)
        expect(resp[:body]).to eq("hi there")
        expect(resp[:headers]["content-type"]).to eq("text/plain")
      end
    end

    it "caps the response body while streaming" do
      with_server(body: "x" * 10_000) do |port|
        transport = described_class.new(request_timeout: 5, max_response_bytes: 1_000)
        uri = URI.parse("http://127.0.0.1:#{port}/big")
        expect { transport.perform("GET", uri, {}, nil, ip_validator: noop_validator) }
          .to raise_error(Enclave::HttpTool::DeniedError, /exceeds/)
      end
    end

    it "calls the IP validator with the resolved addresses" do
      with_server(body: "ok") do |port|
        transport = described_class.new(request_timeout: 5, max_response_bytes: 1_000_000)
        uri = URI.parse("http://127.0.0.1:#{port}/")
        seen = nil
        transport.perform("GET", uri, {}, nil, ip_validator: ->(host, addrs) { seen = [host, addrs] })
        expect(seen[0]).to eq("127.0.0.1")
        expect(seen[1]).to include("127.0.0.1")
      end
    end
  end
end
