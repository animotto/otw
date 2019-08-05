#!/usr/bin/env ruby

require "base64"
require "readline"

class Krypton
  def main(level)
    if !level.nil? && level.to_i >= 1 && level.to_i <= 7 then
      method = "level" + level
      puts "Level %d" % level
      puts
      if self.respond_to?(method) then
        self.method(method).call
      else
        puts "Not implemented yet"
      end
    else
      puts "Level must be between 1-7"
    end
  end

  def level1
    print "Enter Base64 encoded password: "
    cipher = $stdin.gets
    text = Base64.decode64(cipher)
    puts "Decrypted text: %s" % text
  end

  def level2
    print "Enter ciphertext: "
    cipher = $stdin.gets
    text = cipher.tr("a-mA-Mn-zN-Z", "n-zN-Za-mA-M")
    puts "Decrypted text: %s" % text
  end

  def level3
    print "Enter ciphertext: "
    cipher = $stdin.gets
    text = cipher.tr("a-lA-Lm-zM-Z", "o-zO-Za-nA-N")
    puts "Decrypted text: %s" % text
  end


  def level4
    letters = {}
    english = [
      "E", "T", "A", "O", "I", "N", "S", "H", "R", "D", "L", "U", "C",
      "M", "W", "F", "Y", "G", "P", "B", "V", "K", "X", "J", "Q", "Z",
    ]
    
    puts "Enter intercepted messages (empty line ends input)"
    loop do
      print ": "
      line = $stdin.gets
      line.strip!
      break if line.empty?
      line.upcase!
      line.each_char do |letter|
        next unless letter.match?(/[A-Z]/)
        letters[letter] = 0 if letters[letter].nil?
        letters[letter] += 1
      end
    end

    puts
    letters = letters.sort_by {|k, v| -v}
    letters.each_index do |i|
      printf "%s | %03d | " % [letters[i][0], letters[i][1]]
      unless english[i].nil? then
        print "%s" % english[i]
      end
      puts
    end

    dictionary = []
    letters.each_index do |i|
      dictionary[i] = letters[i][0]
    end

    puts
    print "Enter ciphertext: "
    cipher = $stdin.gets
    text = cipher.tr(dictionary.join, english.join)
    puts "Decrypted text: %s" % text
  end
end


krypton = Krypton.new

case ARGV[0]

when "-h"
  puts "Usage: #{__FILE__} [-l <num>]"
  puts " -l <num>    Execute level"
  puts " -h          This help"
  exit
  
when "-l"
  krypton.main(ARGV[1])
  exit

end

loop do
  cmds = Readline.readline("Krypton> ", true)
  next if cmds.nil?
  cmds.strip!
  next if cmds.empty?
  cmds.downcase!
  cmds = cmds.split(/\s+/)
  case cmds[0]
      
  when /^q(uit)?$/
    exit

  when /^h(elp)?$/, "?"
    puts "Available commands:"
    puts " l(evel) <num>    Execute level"
    puts " h(elp)           This help"
    puts " q(uit)           Quit"
    
  when /^l(evel)?$/
    krypton.main(cmds[1])
    
  else
    puts "Unrecognized command"
    
  end
end
