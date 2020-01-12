require 'crabstone'
include Crabstone

cs = Disassembler.new(ARCH_X86, MODE_16)

result = (0x0..0xffff).each_with_object({}) do |num, result|
  hex_string = [num.to_s(16)].pack("H*")

  disassmed = cs.disasm(hex_string, 0x1000)

  disassmed.each do |i|
    mnemonic = i.mnemonic.to_s
    op_str = i.op_str.to_s
    hex = num.to_s(16)

    result["#{mnemonic} #{op_str}"] ||= []
    result["#{mnemonic} #{op_str}"] << hex
  end

rescue Error

end

cs.close

pp selected = result.select { |_, v| v.size > 1 }
pp selected.count

