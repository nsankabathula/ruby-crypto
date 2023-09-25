require 'openssl'
require 'base64'
require 'openssl/oaep'
require 'json'

# Hybrid Encrypt & Decrypt


PUBLIC_CERT_PATH = "./crypto-keys/crypto-enc.pem"
PRIVATE_CERT_PATH = "./crypto-keys/crypto-enc.key"
JSON_PAYLOAD = {"firstName" => "abc"}

def decrypt_session_key(cipher_text_session_key_base64, private_key_path)
    # puts cipher_text_session_key_base64
    private_key = OpenSSL::PKey::RSA.new(File.read private_key_path)
    md_oaep = OpenSSL::Digest::SHA256
    md_mgf1 = OpenSSL::Digest::SHA1
    return private_key.private_decrypt_oaep(Base64.decode64(cipher_text_session_key_base64), '', md_oaep, md_mgf1)
end

def encrypt_session_key(plain_text_session_key, public_cert_path)
    public_cert = OpenSSL::X509::Certificate.new (File.read public_cert_path)
    # puts "#{public_cert.public_key}"
    public_key = OpenSSL::PKey::RSA.new(public_cert.public_key)
    #puts "plain_text_session_key #{plain_text_session_key}"
    md_oaep = OpenSSL::Digest::SHA256
    md_mgf1 = OpenSSL::Digest::SHA1

    cipher_text_session_key = public_key.public_encrypt_oaep(plain_text_session_key, '', md_oaep, md_mgf1)
    cipher_text_session_key_base64 = Base64.encode64(cipher_text_session_key).gsub("","")
    # puts "cipher_text_session_key #{cipher_text_session_key}"
    return cipher_text_session_key_base64
end



# 
def hybrid_encrypt(str_payload)
    encCipher = OpenSSL::Cipher.new('aes-256-gcm')
    encCipher.encrypt
    # Generate random AES key (session-key)
    session_key = encCipher.random_key 
    # puts "session_key >> #{session_key} || #{encCipher.key_len()} bytes \n"

    # Generate random IV
    iv  = encCipher.random_iv 
    # puts "iv >> #{iv} || #{encCipher.iv_len()} bytes \n"

    # AAD
    aad = {"keyId" => "some-keyid", "enc" => "AES-256-GCM", "alg" => "RSA-OAEP"  }

    encCipher.auth_data = aad.to_json

    encCipherText = encCipher.update(str_payload) + encCipher.final
    # puts "encCipherText >> #{encCipherText} || #{encCipherText.bytesize()} || #{Base64.encode64(encCipherText)} \n"
    # puts "authTag >> #{encCipher.auth_tag} || #{encCipher.auth_tag.bytesize()} || #{Base64.encode64(encCipher.auth_tag)} \n"

    # convert to base64 for transmission

    aad_base64 = Base64.encode64(aad.to_json)
    iv_base64 = Base64.encode64(iv)
    
    # puts "iv_base64 >> #{iv_base64} \n"
    # puts "aad_base64 >> #{aad_base64} \n"
    

    # combaining cipher text and auth_tag and encode to base64 for transmission
    combined_cipher_auth_tag_base64 = Base64.encode64(encCipherText.concat(encCipher.auth_tag)) 

    # puts "combined_cipher_auth_tag_base64 >> #{combined_cipher_auth_tag_base64} \n"
    session_details = Base64.encode64({
        "sessionKey" => encrypt_session_key(session_key, PUBLIC_CERT_PATH), # Encrypt the session key using public cert.
        "aad" => aad_base64,
        "keyId" => "some-key-id",
        "iv" => iv_base64
}.to_json)
    secure_details = combined_cipher_auth_tag_base64
    return [session_details, secure_details]
end

def hybrid_decrypt(session_details, secure_details)
    session_details = JSON.parse(Base64.decode64(session_details));
    #puts "session_details #{session_details['sessionKey']}"

    # Decrypt the session key
    session_key = decrypt_session_key(session_details['sessionKey'], PRIVATE_CERT_PATH)

    decCipher = OpenSSL::Cipher.new('aes-256-gcm')
    decCipher.decrypt
    
    # use the decrypted session-key to decrypt the payload/data.
    decCipher.key = session_key
    decCipher.iv = Base64.decode64 (session_details['iv'])
    decCipher.auth_data = Base64.decode64 (session_details['aad'])

    # Split the secure_details => cipher_text & auth_tag (auth_tag is last 16 bytes).
    combined_cipher_auth_tag_base64 = secure_details
    combined_cipher_auth_tag = Base64.decode64 (combined_cipher_auth_tag_base64)
    cipher_text = combined_cipher_auth_tag[0,combined_cipher_auth_tag.bytesize()-16]
    auth_tag = combined_cipher_auth_tag[combined_cipher_auth_tag.bytesize()-16, 16]
    decCipher.auth_tag = auth_tag

    d_plainText = decCipher.update(cipher_text) + decCipher.final
    return d_plainText
end

def test_hybrid()
    cipher_details = hybrid_encrypt(JSON_PAYLOAD.to_json)
    plain_text = hybrid_decrypt(cipher_details[0], cipher_details[1])
    # puts plain_text
    puts "Encrypt vs Decrypt check => #{JSON_PAYLOAD.to_json == plain_text}"

end

puts ("#{test_hybrid()}")