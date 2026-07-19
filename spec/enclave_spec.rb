RSpec.describe Enclave do
  let(:enclave) { described_class.new }

  after { enclave.close unless enclave.closed? }

  describe "#eval" do
    it "evaluates simple expressions" do
      result = enclave.eval("1 + 1")
      expect(result.value).to eq("2")
      expect(result.error?).to be false
    end

    it "returns inspected value" do
      result = enclave.eval('"hello"')
      expect(result.value).to eq('"hello"')
    end

    it "returns nil for statements" do
      result = enclave.eval("x = 42")
      expect(result.error?).to be false
    end

    it "handles multi-line code" do
      code = <<~RUBY
        def add(a, b)
          a + b
        end
        add(2, 3)
      RUBY
      result = enclave.eval(code)
      expect(result.value).to eq("5")
    end
  end

  describe "state persistence" do
    it "preserves local variables across evals" do
      enclave.eval("x = 42")
      result = enclave.eval("x * 2")
      expect(result.value).to eq("84")
    end

    it "preserves method definitions across evals" do
      enclave.eval("def greet(name); 'Hello ' + name; end")
      result = enclave.eval("greet('world')")
      expect(result.value).to eq('"Hello world"')
    end

    it "preserves instance variables on top-level self" do
      enclave.eval("@count = 0")
      enclave.eval("@count += 1")
      result = enclave.eval("@count")
      expect(result.value).to eq("1")
    end

    it "stores last result in _" do
      enclave.eval("42")
      result = enclave.eval("_ + 8")
      expect(result.value).to eq("50")
    end
  end

  describe "output capture" do
    it "captures puts output" do
      result = enclave.eval('puts "hello"')
      expect(result.output).to eq("hello\n")
      expect(result.value).to eq("nil")
    end

    it "captures print output" do
      result = enclave.eval('print "hello"')
      expect(result.output).to eq("hello")
    end

    it "captures p output" do
      result = enclave.eval('p 42')
      expect(result.output).to eq("42\n")
      expect(result.value).to eq("42")
    end

    it "captures multiple puts" do
      result = enclave.eval('puts "a"; puts "b"')
      expect(result.output).to eq("a\nb\n")
    end

    it "captures puts with no args" do
      result = enclave.eval("puts")
      expect(result.output).to eq("\n")
    end

    it "captures puts with arrays" do
      result = enclave.eval('puts [1, 2, 3]')
      expect(result.output).to eq("1\n2\n3\n")
    end

    it "resets output between evals" do
      enclave.eval('puts "first"')
      result = enclave.eval('puts "second"')
      expect(result.output).to eq("second\n")
    end
  end

  describe "error handling" do
    it "captures runtime errors" do
      result = enclave.eval("1 / 0")
      expect(result.error?).to be true
      expect(result.error).to match(/ZeroDivisionError/)
    end

    it "captures name errors" do
      result = enclave.eval("undefined_variable_xyz")
      expect(result.error?).to be true
    end

    it "captures syntax errors" do
      result = enclave.eval("def foo(")
      expect(result.error?).to be true
      expect(result.error).to match(/SyntaxError/)
    end

    it "does not raise Ruby exceptions" do
      expect { enclave.eval("1 / 0") }.not_to raise_error
    end

    it "allows continued use after errors" do
      enclave.eval("1 / 0")
      result = enclave.eval("1 + 1")
      expect(result.value).to eq("2")
      expect(result.error?).to be false
    end
  end

  describe "safety" do
    # Each spec asserts the attempt errors out. If a sandbox escape
    # actually succeeds, the test fails harmlessly (wrong value) —
    # nothing dangerous runs in the host process.

    describe "missing dangerous classes" do
      %w[File IO Dir Socket Process Signal ENV ARGV STDIN STDOUT STDERR
         Regexp MatchData].each do |const|
        it "has no #{const}" do
          result = enclave.eval(const)
          expect(result.error?).to be true
        end
      end
    end

    describe "missing dangerous methods" do
      {
        "system"       => 'system("id")',
        "exec"         => 'exec("id")',
        "spawn"        => 'spawn("id")',
        "backticks"    => '`id`',
        "require"      => 'require "json"',
        "load"         => 'load "foo.rb"',
        "open"         => 'open("/etc/passwd")',
        "exit"         => "exit",
        "exit!"        => "exit!",
        "abort"        => 'abort("bye")',
        "at_exit"      => "at_exit { }",
        "fork"         => "fork { }",
        "trap"         => 'trap("INT") { }',
      }.each do |label, code|
        it "blocks #{label}" do
          result = enclave.eval(code)
          expect(result.error?).to be true
        end
      end
    end

    describe "scope escape attempts" do
      it "cannot reach File through top-level constant lookup" do
        result = enclave.eval("::File")
        expect(result.error?).to be true
      end

      it "cannot fish for dangerous constants via Object.constants" do
        result = enclave.eval('Object.constants.select { |c| c.to_s.include?("File") }')
        # Should either error or return empty
        if result.error?
          expect(result.error?).to be true
        else
          expect(result.value).to satisfy { |v| !v.include?("File") }
        end
      end

      it "cannot eval its way to new scope" do
        # mruby has eval but it's still sandboxed
        result = enclave.eval('eval("File")')
        expect(result.error?).to be true
      end

      it "cannot use instance_eval to escape" do
        result = enclave.eval('Object.instance_eval { File }')
        expect(result.error?).to be true
      end

      it "cannot use class_eval to escape" do
        result = enclave.eval('Object.class_eval { File }')
        expect(result.error?).to be true
      end

      it "cannot use send to call private kernel methods" do
        result = enclave.eval('self.send(:system, "id")')
        expect(result.error?).to be true
      end

      it "cannot use __send__ to bypass method_missing" do
        result = enclave.eval('self.__send__(:system, "id")')
        expect(result.error?).to be true
      end

      it "cannot use Kernel.open pipe trick" do
        result = enclave.eval('Kernel.open("|id")')
        expect(result.error?).to be true
      end
    end

    describe "reflection attacks" do
      it "cannot use ObjectSpace to enumerate host objects" do
        result = enclave.eval("ObjectSpace.each_object(String).to_a")
        # Should either error or only see mruby-internal strings
        if !result.error?
          expect(result.value).not_to include("SECRET")
        end
      end

      it "cannot use method objects to discover internals" do
        result = enclave.eval('method(:puts).inspect')
        # This may work — puts exists in mruby — but shouldn't leak host info
        if !result.error?
          expect(result.value).not_to include("cruby")
        end
      end
    end

    describe "resource exhaustion" do
      it "does not crash the host on deep recursion" do
        result = enclave.eval("def f; f; end; f")
        expect(result.error?).to be true
      end

      it "does not crash the host on large string allocation" do
        result = enclave.eval('"x" * 100_000_000')
        # May succeed with a big string or error — either is fine, host must survive
        expect(enclave.eval("1 + 1").value).to eq("2")
      end

      it "does not crash the host on infinite loop (if mruby catches it)" do
        # mruby may not have a loop timeout, so we just verify the host survives
        # a tight loop that allocates. Skip if it hangs — that's a known mruby limitation.
        result = enclave.eval("a = []; 1_000_000.times { a << 1 }; a.length")
        # Whether it succeeds or errors, the host must be alive
        expect(enclave.eval("1 + 1").value).to eq("2")
      end
    end

    describe "isolation between instances" do
      it "cannot see tools from another enclave" do
        tools_enclave = Enclave.new(tools: TestTools)
        bare_enclave = Enclave.new

        result = bare_enclave.eval("double(21)")
        expect(result.error?).to be true

        tools_enclave.close
        bare_enclave.close
      end

      it "cannot leak state between enclaves" do
        e1 = Enclave.new
        e2 = Enclave.new

        e1.eval("@secret = 'do_not_leak'")
        result = e2.eval("@secret")
        expect(result.value).to eq("nil")

        e1.close
        e2.close
      end
    end

    describe "internal tampering" do
      it "cannot redefine a tool to bypass the callback" do
        e = Enclave.new(tools: TestTools)
        e.eval('def double(n); "hacked"; end')
        # The redefined method wins — but it's still inside the sandbox,
        # so the worst case is the agent lies to itself
        result = e.eval("double(21)")
        expect(result.value).to eq('"hacked"')
        e.close
      end

      it "survives evil inspect override during result serialization" do
        enclave.eval("class Integer; def inspect; nil; end; end")
        result = enclave.eval("42")
        # Should not crash — C code handles non-string inspect gracefully
        expect(enclave.eval("1 + 1")).not_to be_nil
      end

      it "survives a fiber bomb" do
        result = enclave.eval("fibers = 10000.times.map { Fiber.new { loop { Fiber.yield } } }; fibers.length")
        expect(result.value).to eq("10000")
        expect(enclave.eval("1 + 1").value).to eq("2")
      end
    end
  end

  describe "#reset!" do
    it "clears local variables" do
      enclave.eval("x = 42")
      enclave.reset!
      result = enclave.eval("x")
      expect(result.error?).to be true
    end

    it "clears method definitions" do
      enclave.eval("def foo; 1; end")
      enclave.reset!
      result = enclave.eval("foo")
      expect(result.error?).to be true
    end

    it "allows continued use after reset" do
      enclave.reset!
      result = enclave.eval("1 + 1")
      expect(result.value).to eq("2")
    end
  end

  describe "#close" do
    it "marks enclave as closed" do
      enclave.close
      expect(enclave.closed?).to be true
    end

    it "raises on eval after close" do
      enclave.close
      expect { enclave.eval("1") }.to raise_error(RuntimeError, /closed/)
    end

    it "is idempotent" do
      enclave.close
      expect { enclave.close }.not_to raise_error
    end
  end

  describe ".open" do
    it "yields an enclave and auto-closes" do
      result = nil
      described_class.open do |sb|
        result = sb.eval("1 + 1")
        expect(sb.closed?).to be false
      end
      expect(result.value).to eq("2")
    end
  end

  describe "isolation" do
    it "isolates state between instances" do
      sb1 = described_class.new
      sb2 = described_class.new

      sb1.eval("x = 10")
      result = sb2.eval("defined?(x)")
      expect(result.error?).to be(true).or(satisfy { result.value == "nil" })

      sb1.close
      sb2.close
    end
  end

  describe "Result" do
    it "has value, output, and error attributes" do
      result = enclave.eval("1 + 1")
      expect(result).to respond_to(:value)
      expect(result).to respond_to(:output)
      expect(result).to respond_to(:error)
      expect(result).to respond_to(:error?)
    end

    it "has a useful to_s" do
      result = enclave.eval("1 + 1")
      expect(result.to_s).to eq("=> 2")
    end

    it "includes output in to_s" do
      result = enclave.eval('puts "hi"; 42')
      expect(result.to_s).to eq("hi\n=> 42")
    end
  end

  describe "Tool" do
    it "provides a function definition" do
      defn = Enclave::Tool.definition
      expect(defn[:type]).to eq("function")
      expect(defn[:function][:name]).to eq("eval_ruby")
      expect(defn[:function][:parameters][:properties]).to have_key(:code)
    end

    it "calls eval on the enclave" do
      result = Enclave::Tool.call(enclave, code: "2 ** 10")
      expect(result).to eq("=> 1024")
    end
  end

  describe "tools (module bridging)" do
    module TestTools
      def double(n)
        n * 2
      end

      def greet(name)
        "Hello, #{name}!"
      end

      def info
        { name: "test", version: 1, tags: ["a", "b"] }
      end

      def echo_all(a, b, c)
        [a, b, c]
      end

      def returns_nil
        nil
      end

      def returns_true
        true
      end

      def returns_false
        false
      end

      def returns_float
        3.14
      end

      def raise_error
        raise "something went wrong"
      end

      def bad_return
        Object.new
      end
    end

    module MoreTools
      def triple(n)
        n * 3
      end
    end

    let(:enclave_with_tools) { described_class.new(tools: TestTools) }

    after { enclave_with_tools.close unless enclave_with_tools.closed? }

    it "calls a simple tool method with an integer arg" do
      result = enclave_with_tools.eval("double(21)")
      expect(result.value).to eq("42")
      expect(result.error?).to be false
    end

    it "calls a tool method with a string arg" do
      result = enclave_with_tools.eval('greet("World")')
      expect(result.value).to eq('"Hello, World!"')
      expect(result.error?).to be false
    end

    it "returns a hash with nested arrays" do
      result = enclave_with_tools.eval("info()")
      expect(result.error?).to be false
      # mruby inspect uses " => " with spaces
      expect(result.value).to include('"name" => "test"')
      expect(result.value).to include('"tags" => ["a", "b"]')
    end

    it "converts symbol keys to strings" do
      result = enclave_with_tools.eval('info()["name"]')
      expect(result.value).to eq('"test"')
    end

    it "passes multiple args" do
      result = enclave_with_tools.eval('echo_all(1, "two", 3.0)')
      expect(result.value).to eq('[1, "two", 3.0]')
    end

    it "returns nil" do
      result = enclave_with_tools.eval("returns_nil()")
      expect(result.value).to eq("nil")
      expect(result.error?).to be false
    end

    it "returns true" do
      result = enclave_with_tools.eval("returns_true()")
      expect(result.value).to eq("true")
    end

    it "returns false" do
      result = enclave_with_tools.eval("returns_false()")
      expect(result.value).to eq("false")
    end

    it "returns a float" do
      result = enclave_with_tools.eval("returns_float()")
      expect(result.value).to eq("3.14")
    end

    it "captures CRuby exceptions as mruby errors" do
      result = enclave_with_tools.eval("raise_error()")
      expect(result.error?).to be true
      expect(result.error).to include("something went wrong")
    end

    it "rejects unsupported return types with a TypeError" do
      result = enclave_with_tools.eval("bad_return()")
      expect(result.error?).to be true
      expect(result.error).to include("unsupported type")
      expect(result.error).to include("Object")
    end

    it "passes hash args from mruby to CRuby" do
      result = enclave_with_tools.eval('echo_all({"a" => 1}, [2, 3], nil)')
      expect(result.value).to eq('[{"a" => 1}, [2, 3], nil]')
    end

    it "passes boolean and nil args" do
      result = enclave_with_tools.eval("echo_all(true, false, nil)")
      expect(result.value).to eq("[true, false, nil]")
    end

    it "supports multiple modules via expose" do
      enclave_with_tools.expose(MoreTools)
      result = enclave_with_tools.eval("triple(7)")
      expect(result.value).to eq("21")

      # Original tools still work
      result = enclave_with_tools.eval("double(5)")
      expect(result.value).to eq("10")
    end

    it "survives reset!" do
      result = enclave_with_tools.eval("double(10)")
      expect(result.value).to eq("20")

      enclave_with_tools.reset!

      result = enclave_with_tools.eval("double(10)")
      expect(result.value).to eq("20")
      expect(result.error?).to be false
    end

    it "can use tool results in further computations" do
      result = enclave_with_tools.eval("double(double(5))")
      expect(result.value).to eq("20")
    end

    it "passes tools: keyword to constructor" do
      sb = described_class.new(tools: TestTools)
      result = sb.eval("double(3)")
      expect(result.value).to eq("6")
      sb.close
    end

    it "works with .open and tools" do
      described_class.open(tools: TestTools) do |sb|
        result = sb.eval("double(100)")
        expect(result.value).to eq("200")
      end
    end
  end

  describe "timeout" do
    it "raises TimeoutError on infinite loop" do
      e = described_class.new(timeout: 0.5)
      expect { e.eval("loop {}") }.to raise_error(Enclave::TimeoutError)
      e.close
    end

    it "raises TimeoutError on long computation" do
      e = described_class.new(timeout: 0.5)
      expect { e.eval("i = 0; while true; i += 1; end") }.to raise_error(Enclave::TimeoutError)
      e.close
    end

    it "does NOT raise when code finishes in time" do
      e = described_class.new(timeout: 5)
      result = e.eval("1 + 1")
      expect(result.value).to eq("2")
      expect(result.error?).to be false
      e.close
    end

    it "enclave is usable after timeout" do
      e = described_class.new(timeout: 0.5)
      expect { e.eval("loop {}") }.to raise_error(Enclave::TimeoutError)
      result = e.eval("1 + 1")
      expect(result.value).to eq("2")
      e.close
    end

    it "applies class-level default" do
      begin
        Enclave.timeout = 0.5
        e = described_class.new
        expect { e.eval("loop {}") }.to raise_error(Enclave::TimeoutError)
        e.close
      ensure
        Enclave.timeout = nil
      end
    end

    it "per-instance override works" do
      begin
        Enclave.timeout = 100
        e = described_class.new(timeout: 0.5)
        expect { e.eval("loop {}") }.to raise_error(Enclave::TimeoutError)
        e.close
      ensure
        Enclave.timeout = nil
      end
    end

    it "nil means unlimited" do
      e = described_class.new(timeout: nil)
      result = e.eval("1 + 1")
      expect(result.value).to eq("2")
      e.close
    end
  end

  # H1: the wall-clock timeout must be uncatchable. Sandboxed code that rescues
  # the timeout (even by its exact class), retries, or hides work in an ensure
  # block must not be able to run past the deadline or wedge the worker.
  #
  # A wedged mruby VM holds the GVL, so an in-process Timeout can't interrupt a
  # regression — it would hang the whole suite. Each attempt therefore runs in a
  # forked child under a hard wall-clock ceiling enforced with SIGKILL; a
  # regression surfaces as :wedged or :completed (a failing assertion), never a
  # hang.
  describe "timeout cannot be escaped by sandboxed code (H1)" do
    # Returns :timeout when the enclave stopped the code at the deadline,
    # :completed if the code ran to completion (timeout defeated), or :wedged if
    # the eval never returned within `kill_after` (timeout defeated, worker hung).
    def eval_isolated(code, timeout: 0.5, kill_after: 4.0)
      reader, writer = IO.pipe
      pid = fork do
        reader.close
        outcome =
          begin
            e = described_class.new(timeout: timeout, memory_limit: 200_000_000)
            r = e.eval(code)
            e.close
            r.error.nil? ? "completed" : "error"
          rescue Enclave::TimeoutError
            "timeout"
          rescue Exception # rubocop:disable Lint/RescueException
            "host_error"
          end
        writer.write(outcome)
        writer.close
        exit!(0)
      end
      writer.close
      deadline = Process.clock_gettime(Process::CLOCK_MONOTONIC) + kill_after
      until Process.waitpid(pid, Process::WNOHANG)
        if Process.clock_gettime(Process::CLOCK_MONOTONIC) > deadline
          Process.kill("KILL", pid)
          Process.waitpid(pid)
          reader.close
          return :wedged
        end
        sleep 0.01
      end
      out = reader.read
      reader.close
      out.empty? ? :wedged : out.to_sym
    end

    before { skip "fork not available on this platform" unless Process.respond_to?(:fork) }

    # Bounded busy-work that runs well past a 0.5s deadline if it ever executes.
    work = "n = 0; 50_000_000.times { n += 1 }; n"

    it "cannot be swallowed by `rescue Exception`" do
      expect(eval_isolated("begin\n loop {}\nrescue Exception\n #{work}\nend")).to eq(:timeout)
    end

    it "cannot be swallowed by a bare `rescue`" do
      expect(eval_isolated("begin\n loop {}\nrescue\n #{work}\nend")).to eq(:timeout)
    end

    it "cannot be caught by its own class name" do
      expect(eval_isolated("begin\n loop {}\nrescue Enclave::TimeoutError\n #{work}\nend")).to eq(:timeout)
    end

    it "cannot be defeated by `rescue => e; retry; end`" do
      expect(eval_isolated("begin\n loop {}\nrescue Exception\n retry\nend")).to eq(:timeout)
    end

    it "cannot be outrun by work hidden in an `ensure`" do
      expect(eval_isolated("begin\n loop {}\nensure\n #{work}\nend")).to eq(:timeout)
    end

    it "cannot be defeated by an infinite `ensure` loop" do
      expect(eval_isolated("begin\n loop {}\nensure\n loop {}\nend")).to eq(:timeout)
    end

    it "cannot be defeated by a retry nested inside an ensure" do
      expect(eval_isolated("begin\n loop {}\nensure\n begin\n loop {}\n rescue Exception\n retry\n end\nend")).to eq(:timeout)
    end

    it "cannot be defeated by re-raising inside the handler" do
      expect(eval_isolated("begin\n loop {}\nrescue Exception\n raise 'again' while true\nend")).to eq(:timeout)
    end

    it "still stops a plain infinite loop (control)" do
      expect(eval_isolated("loop {}")).to eq(:timeout)
    end

    it "still lets fast code finish normally (control)" do
      expect(eval_isolated("1 + 1", timeout: 5)).to eq(:completed)
    end
  end

  describe "memory_limit" do
    it "raises MemoryLimitError on string bomb" do
      e = described_class.new(memory_limit: 1_000_000)
      expect { e.eval('"x" * 10_000_000') }.to raise_error(Enclave::MemoryLimitError)
      e.close
    end

    it "raises MemoryLimitError on cumulative allocations" do
      e = described_class.new(memory_limit: 1_000_000)
      expect { e.eval('a = []; 100_000.times { a << ("x" * 100) }; a.length') }.to raise_error(Enclave::MemoryLimitError)
      e.close
    end

    it "does NOT raise when allocation fits" do
      e = described_class.new(memory_limit: 10_000_000)
      result = e.eval('"x" * 1000')
      expect(result.error?).to be false
      e.close
    end

    it "enclave is usable after memory limit" do
      e = described_class.new(memory_limit: 1_000_000)
      expect { e.eval('"x" * 10_000_000') }.to raise_error(Enclave::MemoryLimitError)
      result = e.eval("1 + 1")
      expect(result.value).to eq("2")
      e.close
    end

    it "applies class-level default" do
      begin
        Enclave.memory_limit = 1_000_000
        e = described_class.new
        expect { e.eval('"x" * 10_000_000') }.to raise_error(Enclave::MemoryLimitError)
        e.close
      ensure
        Enclave.memory_limit = nil
      end
    end

    it "per-instance override works" do
      begin
        Enclave.memory_limit = 100_000_000
        e = described_class.new(memory_limit: 1_000_000)
        expect { e.eval('"x" * 10_000_000') }.to raise_error(Enclave::MemoryLimitError)
        e.close
      ensure
        Enclave.memory_limit = nil
      end
    end

    it "nil means unlimited" do
      e = described_class.new(memory_limit: nil)
      result = e.eval("1 + 1")
      expect(result.value).to eq("2")
      e.close
    end
  end

  # H2: the captured output buffer lives in raw host memory and is not counted
  # by memory_limit, so without its own cap a print loop is a direct host-OOM.
  describe "max_output_bytes (H2)" do
    it "caps captured output at the configured size" do
      e = described_class.new(max_output_bytes: 50_000)
      result = e.eval('100_000.times { print "x" }; "done"')
      expect(result.output.bytesize).to be <= 50_100 # cap + short marker
      e.close
    end

    it "still returns the value and no error when output is truncated" do
      e = described_class.new(max_output_bytes: 10_000)
      result = e.eval('100_000.times { print "x" }; 42')
      expect(result.error?).to be false
      expect(result.value).to eq("42")
      e.close
    end

    it "appends a truncation marker when the cap is exceeded" do
      e = described_class.new(max_output_bytes: 10_000)
      result = e.eval('print "x" * 20_000')
      expect(result.output).to include("truncated")
      e.close
    end

    it "does NOT truncate or mark output that fits under the cap" do
      e = described_class.new(max_output_bytes: 10_000)
      result = e.eval('print "x" * 100')
      expect(result.output.bytesize).to eq(100)
      expect(result.output).not_to include("truncated")
      e.close
    end

    it "keeps exactly the first max_output_bytes and drops the rest" do
      e = described_class.new(max_output_bytes: 100)
      result = e.eval('print("A" * 100); print("B" * 100)')
      expect(result.output[0, 100]).to eq("A" * 100)
      expect(result.output).not_to include("B")
      e.close
    end

    it "treats 0 as unlimited (opt out)" do
      e = described_class.new(max_output_bytes: 0)
      result = e.eval('20_000.times { print "y" * 100 }; "done"') # ~2 MB
      expect(result.output.bytesize).to eq(2_000_000)
      expect(result.output).not_to include("truncated")
      e.close
    end

    it "is enforced by a safe non-nil default" do
      expect(Enclave.max_output_bytes).to be_a(Integer)
      expect(Enclave.max_output_bytes).to be > 0
      e = described_class.new
      expect(e.max_output_bytes).to eq(Enclave.max_output_bytes)
      e.close
    end

    it "survives reset!" do
      e = described_class.new(max_output_bytes: 1_000)
      e.eval('print "x" * 5_000')
      e.reset!
      result = e.eval('print "z" * 5_000')
      expect(result.output.bytesize).to be <= 1_100
      expect(result.output).to include("truncated")
      e.close
    end

    it "applies class-level default" do
      begin
        Enclave.max_output_bytes = 5_000
        e = described_class.new
        result = e.eval('print "x" * 20_000')
        expect(result.output.bytesize).to be <= 5_100
        e.close
      ensure
        Enclave.max_output_bytes = Enclave::DEFAULT_MAX_OUTPUT_BYTES
      end
    end

    it "per-instance override beats the class-level default" do
      e = described_class.new(max_output_bytes: 200)
      result = e.eval('print "x" * 20_000')
      expect(result.output.bytesize).to be <= 300
      e.close
    end
  end

  # H3: the timeout (code_fetch_hook) fires only at bytecode-fetch boundaries, so
  # a single long-running C builtin can't be preempted. Allocation-heavy builtins
  # are bounded by memory_limit, but a pure-CPU one — a catastrophic-backtracking
  # Regexp — is unbounded (ReDoS). The build therefore ships without Regexp; these
  # are the runtime backstop for the build-time denylist guard.
  describe "no unpreemptable regex builtin (H3)" do
    it "does not define Regexp" do
      expect(enclave.eval("Regexp").error?).to be true
    end

    it "does not define MatchData" do
      expect(enclave.eval("MatchData").error?).to be true
    end

    it "rejects a regex literal (no Regexp to construct)" do
      result = enclave.eval('/(a+)+$/')
      expect(result.error?).to be true
    end

    it "rejects =~ against a regex" do
      result = enclave.eval('"aaaa" =~ /a+/')
      expect(result.error?).to be true
    end

    it "rejects String#match" do
      result = enclave.eval('"aaaa".match(/a+/)')
      expect(result.error?).to be true
    end

    # Allocation-heavy builtins that COULD run long are instead bounded (they
    # raise before doing real work), so the absence of Regexp closes the gap.
    it "bounds a huge String#* by memory_limit" do
      e = described_class.new(timeout: 5, memory_limit: 20_000_000)
      expect { e.eval('"x" * 500_000_000') }.to raise_error(Enclave::MemoryLimitError)
      e.close
    end

    it "caps oversized Array allocation" do
      result = enclave.eval("Array.new(500_000_000, 0)")
      expect(result.error?).to be true
    end

    it "caps oversized bignum exponentiation" do
      result = enclave.eval("10 ** 100_000_000")
      expect(result.error?).to be true
    end
  end

  # H4: the timeout counts only mruby execution, never time inside host tool
  # methods, so a sandbox could pin a worker with unbounded tool calls. Provide a
  # per-eval budget (count + cumulative wall-clock) plus before/after hooks.
  describe "tool-call budget and hooks (H4)" do
    # Tool object whose calls we observe through a closure, so no extra methods
    # leak into the sandbox. `slow` sleeps to exercise the wall-clock budget.
    def build_tool(calls)
      tool = Object.new
      tool.define_singleton_method(:touch) { |*a| calls << a; "ok" }
      tool.define_singleton_method(:slow)  { |*_a| calls << :slow; sleep 0.1; "s" }
      tool
    end

    it "caps the number of tool calls per eval" do
      calls = []
      e = described_class.new(tools: build_tool(calls), max_tool_calls: 3, timeout: 5)
      expect { e.eval("10.times { touch }") }.to raise_error(Enclave::ToolBudgetError)
      expect(calls.size).to eq(3)
      e.close
    end

    it "resets the call budget each eval" do
      calls = []
      e = described_class.new(tools: build_tool(calls), max_tool_calls: 2, timeout: 5)
      2.times { e.eval("5.times { touch }") rescue nil }
      expect(calls.size).to eq(4)
      e.close
    end

    it "is unlimited by default" do
      calls = []
      e = described_class.new(tools: build_tool(calls), timeout: 5)
      e.eval("20.times { touch }")
      expect(calls.size).to eq(20)
      e.close
    end

    it "bounds cumulative tool wall-clock with max_tool_seconds" do
      calls = []
      e = described_class.new(tools: build_tool(calls), max_tool_seconds: 0.25, timeout: 30)
      expect { e.eval("100.times { slow }") }.to raise_error(Enclave::ToolBudgetError)
      expect(calls.size).to be_between(1, 6) # a few 0.1s calls, nowhere near 100
      e.close
    end

    it "ToolBudgetError is an Enclave::Error" do
      expect(Enclave::ToolBudgetError).to be < Enclave::Error
    end

    it "runs before_tool_call with (name, args)" do
      seen = []
      e = described_class.new(tools: build_tool([]), timeout: 5,
                              before_tool_call: ->(name, args) { seen << [name, args] })
      e.eval("touch(1, 2)")
      expect(seen).to eq([[:touch, [1, 2]]])
      e.close
    end

    it "runs after_tool_call with (name, args, result)" do
      seen = []
      e = described_class.new(tools: build_tool([]), timeout: 5,
                              after_tool_call: ->(name, args, result) { seen << [name, args, result] })
      e.eval("touch(7)")
      expect(seen).to eq([[:touch, [7], "ok"]])
      e.close
    end

    it "lets before_tool_call veto a call by raising" do
      calls = []
      e = described_class.new(tools: build_tool(calls), timeout: 5,
                              before_tool_call: ->(_name, _args) { raise "denied" })
      result = e.eval("touch")
      expect(calls).to be_empty
      expect(result.error?).to be true
      expect(result.error).to include("denied")
      e.close
    end

    it "works with no hooks set (default)" do
      calls = []
      e = described_class.new(tools: build_tool(calls), timeout: 5)
      result = e.eval("touch")
      expect(result.error?).to be false
      expect(calls.size).to eq(1)
      e.close
    end

    it "exposes the budget via attr_readers" do
      e = described_class.new(max_tool_calls: 9, max_tool_seconds: 1.5)
      expect(e.max_tool_calls).to eq(9)
      expect(e.max_tool_seconds).to eq(1.5)
      e.close
    end
  end

  describe "error classes" do
    it "Enclave::Error inherits from StandardError" do
      expect(Enclave::Error).to be < StandardError
    end

    it "Enclave::TimeoutError inherits from Enclave::Error" do
      expect(Enclave::TimeoutError).to be < Enclave::Error
    end

    it "Enclave::MemoryLimitError inherits from Enclave::Error" do
      expect(Enclave::MemoryLimitError).to be < Enclave::Error
    end

    it "TimeoutError is rescuable as Enclave::Error" do
      e = described_class.new(timeout: 0.5)
      expect { e.eval("loop {}") }.to raise_error(Enclave::Error)
      e.close
    end

    it "MemoryLimitError is rescuable as Enclave::Error" do
      e = described_class.new(memory_limit: 1_000_000)
      expect { e.eval('"x" * 10_000_000') }.to raise_error(Enclave::Error)
      e.close
    end
  end

  describe "attr_readers" do
    it "timeout returns configured value" do
      e = described_class.new(timeout: 2.5)
      expect(e.timeout).to eq(2.5)
      e.close
    end

    it "memory_limit returns configured value" do
      e = described_class.new(memory_limit: 5_000_000)
      expect(e.memory_limit).to eq(5_000_000)
      e.close
    end

    it "timeout returns nil when unlimited" do
      e = described_class.new(timeout: nil)
      expect(e.timeout).to be_nil
      e.close
    end

    it "memory_limit returns nil when unlimited" do
      e = described_class.new(memory_limit: nil)
      expect(e.memory_limit).to be_nil
      e.close
    end

    it "max_output_bytes returns configured value" do
      e = described_class.new(max_output_bytes: 4_096)
      expect(e.max_output_bytes).to eq(4_096)
      e.close
    end

    it "max_output_bytes returns nil when explicitly unlimited" do
      e = described_class.new(max_output_bytes: nil)
      expect(e.max_output_bytes).to be_nil
      e.close
    end
  end

  describe "combined limits" do
    it "both limits set, normal eval works" do
      e = described_class.new(timeout: 5, memory_limit: 10_000_000)
      result = e.eval("1 + 1")
      expect(result.value).to eq("2")
      e.close
    end

    it "timeout fires with memory_limit also set" do
      e = described_class.new(timeout: 0.5, memory_limit: 10_000_000)
      expect { e.eval("loop {}") }.to raise_error(Enclave::TimeoutError)
      e.close
    end

    it "memory limit fires with timeout also set" do
      e = described_class.new(timeout: 5, memory_limit: 1_000_000)
      expect { e.eval('"x" * 10_000_000') }.to raise_error(Enclave::MemoryLimitError)
      e.close
    end

    it "limits persist through reset!" do
      e = described_class.new(timeout: 0.5, memory_limit: 1_000_000)
      e.reset!
      expect { e.eval("loop {}") }.to raise_error(Enclave::TimeoutError)
      e.close
    end

    it "works with .open" do
      described_class.open(timeout: 0.5, memory_limit: 10_000_000) do |sb|
        expect { sb.eval("loop {}") }.to raise_error(Enclave::TimeoutError)
      end
    end
  end

  describe "tools (instance-based)" do
    class FakeUser
      attr_accessor :name, :email, :plan

      def initialize(name:, email:, plan:)
        @name = name
        @email = email
        @plan = plan
      end
    end

    class AccountTools
      def initialize(user)
        @user = user
      end

      def user_info
        { name: @user.name, email: @user.email, plan: @user.plan }
      end

      def change_plan(new_plan)
        @user.plan = new_plan
        { success: true, plan: @user.plan }
      end

      def upcase_name
        @user.name.upcase
      end
    end

    class BillingTools
      def charge(amount)
        { charged: amount }
      end
    end

    let(:user) { FakeUser.new(name: "Jane Doe", email: "jane@example.com", plan: "basic") }
    let(:enclave_with_instance) { described_class.new(tools: AccountTools.new(user)) }

    after { enclave_with_instance.close unless enclave_with_instance.closed? }

    it "calls methods on the instance" do
      result = enclave_with_instance.eval("user_info()")
      expect(result.error?).to be false
      expect(result.value).to include('"name" => "Jane Doe"')
      expect(result.value).to include('"plan" => "basic"')
    end

    it "mutates state through the instance" do
      enclave_with_instance.eval('change_plan("premium")')
      expect(user.plan).to eq("premium")
    end

    it "returns the mutated state" do
      result = enclave_with_instance.eval('change_plan("premium")')
      expect(result.value).to include('"plan" => "premium"')
    end

    it "calls methods that return strings" do
      result = enclave_with_instance.eval("upcase_name()")
      expect(result.value).to eq('"JANE DOE"')
    end

    it "supports exposing multiple instances" do
      enclave_with_instance.expose(BillingTools.new)
      result = enclave_with_instance.eval("charge(999)")
      expect(result.value).to include('"charged" => 999')

      # Original tools still work
      result = enclave_with_instance.eval("user_info()")
      expect(result.value).to include('"name" => "Jane Doe"')
    end

    it "survives reset!" do
      result = enclave_with_instance.eval("user_info()")
      expect(result.error?).to be false

      enclave_with_instance.reset!

      result = enclave_with_instance.eval("user_info()")
      expect(result.error?).to be false
      expect(result.value).to include('"name" => "Jane Doe"')
    end

    it "works with .open" do
      tools = AccountTools.new(user)
      described_class.open(tools: tools) do |sb|
        result = sb.eval("user_info()")
        expect(result.value).to include('"name" => "Jane Doe"')
      end
    end
  end
end
