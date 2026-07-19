require_relative "enclave/version"
require_relative "enclave/result"
require_relative "enclave/tool"
begin
  require_relative "enclave/enclave"
rescue LoadError
  raise LoadError,
    "Enclave native extension not found. Run `rake compile` first (from a git clone, run `rake setup`)."
end

class Enclave
  # Default cap on captured puts/print/p output. The output buffer lives in raw
  # host memory and is NOT counted by memory_limit, so it needs its own bound or
  # a print loop is a direct host-OOM (H2). This default is deliberately non-nil
  # so hosts are protected out of the box; set max_output_bytes: nil for
  # unlimited (matching timeout/memory_limit, where nil means unlimited).
  DEFAULT_MAX_OUTPUT_BYTES = 10 * 1024 * 1024

  class << self
    attr_accessor :timeout, :memory_limit, :max_output_bytes, :max_tool_calls, :max_tool_seconds
  end
  self.max_output_bytes = DEFAULT_MAX_OUTPUT_BYTES

  attr_reader :timeout, :memory_limit, :max_output_bytes, :max_tool_calls, :max_tool_seconds

  # Hooks invoked around every tool call (H4). Callables (or nil):
  #   before_tool_call.call(name_symbol, args_array)          — may raise to veto
  #   after_tool_call.call(name_symbol, args_array, result)
  # Use them to meter, log, or rate-limit without monkey-patching. The tool-call
  # budget (max_tool_calls / max_tool_seconds) is enforced separately, in C.
  attr_accessor :before_tool_call, :after_tool_call

  def initialize(tools: nil, timeout: self.class.timeout, memory_limit: self.class.memory_limit,
                 max_output_bytes: self.class.max_output_bytes,
                 max_tool_calls: self.class.max_tool_calls, max_tool_seconds: self.class.max_tool_seconds,
                 before_tool_call: nil, after_tool_call: nil)
    @tool_context = Object.new
    @timeout = timeout
    @memory_limit = memory_limit
    @max_output_bytes = max_output_bytes
    @max_tool_calls = max_tool_calls
    @max_tool_seconds = max_tool_seconds
    @before_tool_call = before_tool_call
    @after_tool_call = after_tool_call
    _init(@timeout, @memory_limit, @max_output_bytes, @max_tool_calls, @max_tool_seconds)
    expose(tools) if tools
  end

  def self.open(tools: nil, timeout: self.timeout, memory_limit: self.memory_limit,
                max_output_bytes: self.max_output_bytes,
                max_tool_calls: self.max_tool_calls, max_tool_seconds: self.max_tool_seconds,
                before_tool_call: nil, after_tool_call: nil)
    sandbox = new(tools: tools, timeout: timeout, memory_limit: memory_limit,
                  max_output_bytes: max_output_bytes,
                  max_tool_calls: max_tool_calls, max_tool_seconds: max_tool_seconds,
                  before_tool_call: before_tool_call, after_tool_call: after_tool_call)
    begin
      yield sandbox
    ensure
      sandbox.close
    end
  end

  def eval(code)
    value, output, error = _eval(code)
    Result.new(value: value, output: output, error: error)
  end

  def repl
    require "readline"
    buf = ""
    prompt = "enclave> "

    puts "Enclave REPL (#{RUBY_ENGINE} host, mruby sandbox)"
    puts "Type 'exit' or Ctrl-D to quit.\n\n"

    while (line = Readline.readline(buf.empty? ? prompt : "     .. ", true))
      break if buf.empty? && line.strip == "exit"

      buf << line << "\n"
      result = eval(buf)

      if result.error? && result.error.match?(/SyntaxError.*unexpected.*\$end|unexpected end of file/i)
        next # incomplete input, keep reading
      end

      print result.output unless result.output.empty?
      if result.error?
        puts "Error: #{result.error}"
      else
        puts "=> #{result.value}"
      end
      buf = ""
    end

    puts "\n" if line.nil? # clean newline on Ctrl-D
  end

  def expose(obj)
    case obj
    when Module
      @tool_context.extend(obj)
      obj.instance_methods(false).each do |name|
        _define_function(name.to_s)
      end
    else
      obj.public_methods(false).each do |name|
        target = obj
        @tool_context.define_singleton_method(name) { |*args| target.public_send(name, *args) }
        _define_function(name.to_s)
      end
    end
    self
  end

  private

  # Invoked from the C tool trampoline for every tool call, so the before/after
  # hooks wrap the actual dispatch. A raise in before_tool_call vetoes the call.
  # Not registered as a sandbox function, so untrusted code cannot reach it.
  def __dispatch_tool(name, args)
    @before_tool_call&.call(name, args)
    result = @tool_context.__send__(name, *args)
    @after_tool_call&.call(name, args, result)
    result
  end
end
