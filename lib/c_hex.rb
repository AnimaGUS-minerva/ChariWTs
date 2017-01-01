class CHex
  def self.parse(string)
    binary = ''

    upper = true
    comment = false
    tempnum = 0
    string.split("").each {|char|

      if comment
        if char == "\n"
          comment = false
        end
        next
      end

      nchar = char.downcase
      #puts "char: '#{nchar}' tempnum:#{tempnum}"

      number=0
      case nchar
      when '0'
        number=0
      when '1'
        number=1
      when '2'
        number=2
      when '3'
        number=3
      when '4'
        number=4
      when '5'
        number=5
      when '6'
        number=6
      when '7'
        number=7
      when '8'
        number=8
      when '9'
        number=9
      when 'a'
        number=10
      when 'b'
        number=11
      when 'c'
        number=12
      when 'd'
        number=13
      when 'e'
        number=14
      when 'f'
        number=15
      when '#'
        comment = true
      else
        #puts "  ..skipped"
        next
      end

      #puts "number: #{number}"

      if upper
        tempnum = number << 4
        upper   = false
      else
        tempnum += number
        binary  += tempnum.chr
        upper   = true
      end
    }
    binary
    end
end
