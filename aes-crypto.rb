require 'openssl'
require "base64"
require 'json'



## AES Encryption

plainText = {"a" => "b"}

encCipher = OpenSSL::Cipher.new('aes-256-gcm')
encCipher.encrypt
aesKey = encCipher.random_key # Generated random AES key 
# puts "aesKey >> #{aesKey} || #{encCipher.key_len()} bytes \n"

iv  = encCipher.random_iv # Generate random IV
# puts "iv >> #{iv} || #{encCipher.iv_len()} bytes \n"

aad = {"keyId" => "some-keyid", "enc" => "AES-256-GCM", "alg" => "RSA-OAEP"  }

encCipher.auth_data = aad.to_json

encCipherText = encCipher.update(plainText.to_json) + encCipher.final
# puts "encCipherText >> #{encCipherText} || #{encCipherText.bytesize()} || #{Base64.encode64(encCipherText)} \n"
# puts "authTag >> #{encCipher.auth_tag} || #{encCipher.auth_tag.bytesize()} || #{Base64.encode64(encCipher.auth_tag)} \n"

# convert to base64 for transmission

aad_base64 = Base64.encode64(aad.to_json)
iv_base64 = Base64.encode64(iv)
aes_key_base64 = Base64.encode64(aesKey)

puts "iv_base64 >> #{iv_base64} \n"
puts "aad_base64 >> #{aad_base64} \n"
puts "aes_key_base64 >> #{aes_key_base64} \n"

# combaining cipher text and auth_tag and encode to base64 for transmission
combined_cipher_auth_tag_base64 = Base64.encode64(encCipherText.concat(encCipher.auth_tag)) 
puts "combined_cipher_auth_tag_base64 >> #{combined_cipher_auth_tag_base64} \n"


## AES Decryption (Assuming all data is encoded to base64)


decCipher = OpenSSL::Cipher.new('aes-256-gcm')
decCipher.decrypt

decCipher.key = Base64.decode64(aes_key_base64)
decCipher.iv = Base64.decode64 (iv_base64)
decCipher.auth_data = Base64.decode64 (aad_base64)

combined_cipher_auth_tag = Base64.decode64 (combined_cipher_auth_tag_base64)
cipher_text = combined_cipher_auth_tag[0,combined_cipher_auth_tag.bytesize()-16]
auth_tag = combined_cipher_auth_tag[combined_cipher_auth_tag.bytesize()-16, 16]
decCipher.auth_tag = auth_tag

d_plainText = decCipher.update(cipher_text) + decCipher.final

puts "Decrypt plainText = #{d_plainText} \n"

