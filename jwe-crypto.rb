require 'jwe'


PUBLIC_CERT_PATH = "./crypto-keys/crypto-enc.pem"
PRIVATE_CERT_PATH = "./crypto-keys/crypto-enc.key"
JSON_PAYLOAD = {"firstName" => "abc"}

def jwe_encrypt(string_payload, public_cert_path)
    public_cert = OpenSSL::X509::Certificate.new (File.read public_cert_path)
        # puts "#{public_cert.public_key}"
    public_key = OpenSSL::PKey::RSA.new(public_cert.public_key)
    jwe_token = JWE.encrypt(string_payload, public_key, enc: 'A256GCM')
    puts jwe_token
    return jwe_token
end

def jwe_decrypt(jwe_token, private_key_path)
    private_key = OpenSSL::PKey::RSA.new(File.read private_key_path)
    plain_text = JWE.decrypt(jwe_token, private_key)
    puts plain_text
    return plain_text
end

def jwe_test()
    token = jwe_encrypt(JSON_PAYLOAD.to_json, PUBLIC_CERT_PATH)
    decrypted_payload = jwe_decrypt(token, PRIVATE_CERT_PATH)
    puts decrypted_payload == JSON_PAYLOAD.to_json
end

jwe_test()
