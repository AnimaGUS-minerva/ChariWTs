require 'base64'
require 'ecdsa'

sig01_key_base64 = {
    kty:"EC",
    kid:"11",
    crv:"P-256",
    x:"usWxHK2PmfnHKwXPS54m0kTcGJ90UiglWiGahtagnv8",
    y:"IBOL-C3BttVivg-lSreASjpkttcsz-1rb7btKLv8EX4",
    d:"V8kgd2ZBRuh2dgyVINBUqpPDr7BOMGcF22CQMIUHtNM"
}

private_key = ECDSA::Format::IntegerOctetString.decode(Base64.urlsafe_decode64(sig01_key_base64[:d]))

bx=ECDSA::Format::IntegerOctetString.decode(Base64.urlsafe_decode64(sig01_key_base64[:x]))
basey=Base64.urlsafe_decode64(sig01_key_base64[:y])
encodey=Base64.encode64(basey)

by=ECDSA::Format::IntegerOctetString.decode(basey)

group        = ECDSA::Group::Nistp256
sig01_pub_key= group.new_point([bx, by])

public_key  = group.generator.multiply_by_scalar(private_key)

puts "derived x: #{public_key.x} "
puts "       vs: #{sig01_pub_key.x}"

puts "derived y: #{public_key.y} "
puts "       vs: #{sig01_pub_key.y}"

puts "y bits: #{public_key.y.to_s(2)}"
puts "y bits: #{sig01_pub_key.y.to_s(2)}"

puts "basey: #{sig01_key_base64[:y]}"
puts "encoy: #{encodey}"

