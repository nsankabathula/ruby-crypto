require 'openssl'
require 'base64'
require 'openssl/oaep'

PUBLIC_CERT_PATH = "./crypto-keys/crypto-enc.pem"
PRIVATE_CERT_PATH = "./crypto-keys/crypto-enc.key"
MD_OAEP = OpenSSL::Digest::SHA256
MD_MGF1 = OpenSSL::Digest::SHA1
PLAIN_TEXT = "random-aes-keymnbnbbkbkhkhkhkjhkhkhkhkjhkhkhkjhkjhkjhkjhkjhkjhkjhkjhkhkhkhdgdgd"


def encrypt()
    public_cert = OpenSSL::X509::Certificate.new (File.read PUBLIC_CERT_PATH)
    # puts "#{public_cert.public_key}"
    public_key = OpenSSL::PKey::RSA.new(public_cert.public_key)
    cipher_text = public_key.public_encrypt_oaep(PLAIN_TEXT, '', MD_OAEP, MD_MGF1)
    return cipher_text
end

def decrypt(cipher_text)
    private_key = OpenSSL::PKey::RSA.new(File.read PRIVATE_CERT_PATH)
    decrypted_PLAIN_TEXT = private_key.private_decrypt_oaep(cipher_text, '', MD_OAEP, MD_MGF1)
    # puts "decrypted_PLAIN_TEXT #{decrypted_PLAIN_TEXT} \n"
    return decrypted_PLAIN_TEXT
end

def test()
    puts "Encrypt == Decrypt check => #{PLAIN_TEXT == decrypt(encrypt())}"
    puts "Signature verify => #{verify(PLAIN_TEXT, sign(PLAIN_TEXT))}"
end

def sign(payload)
    private_key = OpenSSL::PKey::RSA.new(File.read PRIVATE_CERT_PATH)
    signature = private_key.sign_pss("SHA256", payload, salt_length: :max, mgf1_hash: "SHA256")
    return signature
end

def verify(payload, signature)
    public_cert = OpenSSL::X509::Certificate.new (File.read PUBLIC_CERT_PATH)
    public_key = OpenSSL::PKey::RSA.new(public_cert.public_key)
    return public_key.verify_pss("SHA256", signature, payload, salt_length: :auto, mgf1_hash: "SHA256") 
end


test()



