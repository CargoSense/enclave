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

  # Optional error sanitizer (H6). When a tool method raises, its message
  # (exc.inspect) otherwise crosses back into the sandbox verbatim — leaking host
  # internals (SQL, file paths, IDs, third-party error bodies) to untrusted code.
  # Set a callable to map the exception to a safe message the sandbox may see,
  # e.g. ->(name, exc) { logger.error(exc.full_message); "#{name} failed" }.
  # nil (default) passes the original message through. Only tool-method
  # exceptions are sanitized — before/after_tool_call raises pass through, since
  # those messages are yours.
  attr_accessor :error_sanitizer

  def initialize(tools: nil, timeout: self.class.timeout, memory_limit: self.class.memory_limit,
                 max_output_bytes: self.class.max_output_bytes,
                 max_tool_calls: self.class.max_tool_calls, max_tool_seconds: self.class.max_tool_seconds,
                 before_tool_call: nil, after_tool_call: nil, error_sanitizer: nil)
    @tool_context = Object.new
    @timeout = timeout
    @memory_limit = memory_limit
    @max_output_bytes = max_output_bytes
    @max_tool_calls = max_tool_calls
    @max_tool_seconds = max_tool_seconds
    @before_tool_call = before_tool_call
    @after_tool_call = after_tool_call
    @error_sanitizer = error_sanitizer
    @exposed_functions = []
    _init(@timeout, @memory_limit, @max_output_bytes, @max_tool_calls, @max_tool_seconds)
    expose(tools) if tools
  end

  def self.open(tools: nil, timeout: self.timeout, memory_limit: self.memory_limit,
                max_output_bytes: self.max_output_bytes,
                max_tool_calls: self.max_tool_calls, max_tool_seconds: self.max_tool_seconds,
                before_tool_call: nil, after_tool_call: nil, error_sanitizer: nil)
    sandbox = new(tools: tools, timeout: timeout, memory_limit: memory_limit,
                  max_output_bytes: max_output_bytes,
                  max_tool_calls: max_tool_calls, max_tool_seconds: max_tool_seconds,
                  before_tool_call: before_tool_call, after_tool_call: after_tool_call,
                  error_sanitizer: error_sanitizer)
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

  # The tool function names (symbols) currently reachable from the sandbox — the
  # exact capability surface. Assert on this in a test to catch a public method
  # that leaked in by accident.
  def exposed_functions
    @exposed_functions.dup
  end

  # Publish an object's (or module's) public methods as sandbox tools.
  #
  # By default EVERY public method becomes callable from untrusted code, so a
  # helper you forget to make private is silently reachable. Narrow the surface
  # explicitly:
  #
  #   expose(tools, only:   %i[search fetch])   # allowlist (recommended)
  #   expose(tools, except: %i[internal_cache]) # denylist
  #
  # Names in only:/except: that aren't exposable public methods raise
  # ArgumentError, so a typo can't silently widen (except:) or misname (only:)
  # the surface.
  def expose(obj, only: nil, except: nil)
    raise ArgumentError, "expose: pass only: or except:, not both" if only && except

    is_module = obj.is_a?(Module)
    candidates = (is_module ? obj.instance_methods(false) : obj.public_methods(false)).map(&:to_sym)
    names = filter_exposed(candidates, only: only, except: except)

    @tool_context.extend(obj) if is_module

    names.each do |name|
      unless is_module
        target = obj
        @tool_context.define_singleton_method(name) { |*args| target.public_send(name, *args) }
      end
      _define_function(name.to_s)
      @exposed_functions << name unless @exposed_functions.include?(name)
    end
    self
  end

  private

  # Resolve only:/except: against the exposable candidates, rejecting names that
  # don't exist so silent surface changes can't slip through.
  def filter_exposed(candidates, only:, except:)
    if only
      requested = Array(only).map(&:to_sym)
      unknown = requested - candidates
      raise ArgumentError, "expose only: not an exposable public method: #{unknown.join(', ')}" unless unknown.empty?
      requested
    elsif except
      excluded = Array(except).map(&:to_sym)
      unknown = excluded - candidates
      raise ArgumentError, "expose except: not an exposable public method: #{unknown.join(', ')}" unless unknown.empty?
      candidates - excluded
    else
      candidates
    end
  end

  # Invoked from the C tool trampoline for every tool call, so the before/after
  # hooks wrap the actual dispatch. A raise in before_tool_call vetoes the call.
  # Not registered as a sandbox function, so untrusted code cannot reach it.
  def __dispatch_tool(name, args)
    @before_tool_call&.call(name, args)
    result =
      begin
        @tool_context.__send__(name, *args)
      rescue Exception => e # rubocop:disable Lint/RescueException
        # Sanitize only the tool method's own error before it crosses back.
        raise sanitized_tool_error(name, e)
      end
    @after_tool_call&.call(name, args, result)
    result
  end

  # Map a tool exception to what the sandbox is allowed to see. With no
  # sanitizer, the original exception passes through unchanged (default). A
  # sanitizer that itself raises must never leak the original, so it falls back
  # to a generic message.
  def sanitized_tool_error(name, exc)
    return exc if @error_sanitizer.nil?

    message =
      begin
        @error_sanitizer.call(name, exc)
      rescue Exception # rubocop:disable Lint/RescueException
        nil
      end
    RuntimeError.new(message.nil? ? "tool call failed" : message.to_s)
  end
end
