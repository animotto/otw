#!/usr/bin/env ruby

require "readline"
require "socket"

##
# Vortex wargame
class Vortex
  HOST = "vortex.labs.overthewire.org"
  PORT_LEVEL0 = 5842

  ##
  # Executes level:
  #   level = Level
  def exec(level)
    raise "Level must be between 0-27" unless level >= 0 && level <= 27
    method = "level#{level}"
    raise "Not implemented yet" if !self.respond_to?(method)

    @logger = Logger.new(level)
    begin
      self.method(method).call
    rescue => e
      @logger.error(e)
    end
  end

  ##
  # Level 0
  def level0
    @logger.action("Connectig to #{HOST}:#{PORT_LEVEL0}")
    socket = TCPSocket.new(HOST, PORT_LEVEL0)

    @logger.action("Reading data")
    data = socket.read(16)
    @logger.info("Received bytes: " + data.each_byte.map {|byte| "%02x" % byte}.join(" "))

    sum = 0
    data.unpack("L<4").each_with_index do |num, i|
      @logger.info("Num#{i}: #{num}")
      sum += num
    end

    @logger.action("Sending sum")
    socket.write([sum].pack("L<"))
    data = socket.read
    @logger.success(data)

    socket.close
  end
end

##
# Logger
class Logger
  ##
  # Creates new logger:
  #   level = Level
  def initialize(level)
    @level = level
  end

  ##
  # Logs info message:
  #   message = Message
  def info(message)
    print(5, message)
  end

  ##
  # Logs action message:
  #   message = Message
  def action(message)
    print(6, message)
  end

  ##
  # Logs success message:
  #   message = Message
  def success(message)
    print(2, message)
  end

  ##
  # Logs error message:
  #   message = Message
  def error(message)
    print(1, message)
  end

  private

  ##
  # Prints message:
  #   color   = Color
  #   message = Message
  #   nl      = Print new line
  def print(color, message, nl = true)
    $stdout.print("\e[34;1m[Level#{@level}] \e[#{30 + color};22m#{message}\e[0m")
    $stdout.puts if nl
  end
end

Signal.trap("SIGINT") {exit}

commands = {
  "level"    => ["level <0-27>", "Exec level"],
  "help"     => ["help", "This help"],
  "quit"     => ["quit", "Quit"],
}

Readline.completion_proc = Proc.new do |s|
  commands.keys.grep(/^#{Regexp.escape(s)}/)
end

vortex = Vortex.new
loop do
  line = Readline.readline("\e[33;1mVortex>\e[0m ", true)
  exit if line.nil?
  line.strip!
  if line.empty?
    Readline::HISTORY.pop
    next
  end

  words = line.split(/\s+/)
  case words[0].downcase
    when "help", "?"
      commands.each do |k, v|
        puts "%-20s%s" % [v[0], v[1]]
      end

    when "quit"
      exit

    when "level"
      if words[1].nil?
        puts "Specify level"
        next
      end

      level = words[1].to_i
      begin
        vortex.exec(level)
      rescue => e
        puts e
      end

    else
      puts "Unrecognized command"
  end
end

