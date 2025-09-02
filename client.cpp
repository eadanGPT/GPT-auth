// main.cpp
// C++ client for the Node server: RSA-OAEP(SHA-256) -> AES-256-GCM transport, JWT auth, heartbeats, random checks, challenge handling.

#include <iostream>
#include <string>
#include <thread>
#include <atomic>
#include <vector>
#include <random>
#include <chrono>
#include <iomanip>
#include <sstream>
#include <stdexcept>
#include <mutex>
#include <condition_variable>

#include <boost/asio.hpp>
#include <boost/beast.hpp>
#include <boost/beast/websocket.hpp>
#include <boost/beast/core/flat_buffer.hpp>
#include <boost/beast/websocket/stream.hpp>
#include <boost/beast/http.hpp>

#include <openssl/evp.h>
#include <openssl/pem.h>
#include <openssl/rsa.h>
#include <openssl/rand.h>
#include <openssl/hmac.h>

#include "nlohmann/json.hpp"

using json = nlohmann::json;
namespace asio = boost::asio;
namespace beast = boost::beast;
namespace http  = beast::http;
namespace ws    = beast::websocket;
using tcp = asio::ip::tcp;

// -------------------------- Utilities --------------------------

static std::string base64(const std::vector<unsigned char>& in) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new(BIO_s_mem());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    b64 = BIO_push(b64, mem);
    BIO_write(b64, in.data(), (int)in.size());
    BIO_flush(b64);
    BUF_MEM* bptr;
    BIO_get_mem_ptr(b64, &bptr);
    std::string out(bptr->data, bptr->length);
    BIO_free_all(b64);
    return out;
}
static std::vector<unsigned char> base64_decode_vec(const std::string& s) {
    BIO* b64 = BIO_new(BIO_f_base64());
    BIO* mem = BIO_new_mem_buf(s.data(), (int)s.size());
    BIO_set_flags(b64, BIO_FLAGS_BASE64_NO_NL);
    mem = BIO_push(b64, mem);
    std::vector<unsigned char> out(s.size());
    int len = BIO_read(mem, out.data(), (int)out.size());
    if (len < 0) len = 0;
    out.resize((size_t)len);
    BIO_free_all(mem);
    return out;
}
static std::string b64url_from_bytes(const unsigned char* data, size_t len) {
    // base64 then URL-safe (no padding)
    std::vector<unsigned char> vec(data, data + len);
    std::string b64s = base64(vec);
    for (auto& c : b64s) { if (c=='+') c='-'; else if (c=='/') c='_'; }
    while (!b64s.empty() && b64s.back()=='=') b64s.pop_back();
    return b64s;
}
static std::string b64url_from_string(const std::string& s) {
    return b64url_from_bytes(reinterpret_cast<const unsigned char*>(s.data()), s.size());
}
static std::vector<unsigned char> b64_to_vec(const std::string& s) {
    return base64_decode_vec(s);
}
static std::string to_hex(const std::vector<unsigned char>& v) {
    std::ostringstream oss;
    for (auto c : v) oss << std::hex << std::setw(2) << std::setfill('0') << (int)c;
    return oss.str();
}

static std::string uuid_v4() {
    std::random_device rd;
    std::mt19937 gen(rd());
    std::uniform_int_distribution<uint32_t> dist(0, 0xFFFFFFFF);

    uint32_t d[4] = { dist(gen), dist(gen), dist(gen), dist(gen) };
    // Set version (4) and variant (10)
    d[1] = (d[1] & 0xFFFF0FFFu) | 0x00004000u;
    d[2] = (d[2] & 0x3FFFFFFFu) | 0x80000000u;
    std::ostringstream oss;
    oss << std::hex << std::setfill('0')
        << std::setw(8) << d[0] << "-"
        << std::setw(4) << (d[1] >> 16) << "-"
        << std::setw(4) << (d[1] & 0xFFFF) << "-"
        << std::setw(4) << (d[2] >> 16) << "-"
        << std::setw(4) << (d[2] & 0xFFFF)
        << std::setw(8) << d[3];
    return oss.str();
}

// -------------------------- OpenSSL helpers --------------------------

struct AESPacket {
    std::string iv_b64;
    std::string tag_b64;
    std::string data_b64;
};

static std::vector<unsigned char> aes_gcm_encrypt(const std::vector<unsigned char>& key32,
                                                  const std::vector<unsigned char>& plaintext,
                                                  std::vector<unsigned char>& iv_out, // 12 bytes
                                                  std::vector<unsigned char>& tag_out) {
    iv_out.resize(12);
    RAND_bytes(iv_out.data(), (int)iv_out.size());

    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_EncryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("EncryptInit_ex failed");
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv_out.size(), nullptr) != 1)
        throw std::runtime_error("GCM set IV len failed");
    if (EVP_EncryptInit_ex(ctx, nullptr, nullptr, key32.data(), iv_out.data()) != 1)
        throw std::runtime_error("EncryptInit_ex key/iv failed");

    std::vector<unsigned char> out(plaintext.size() + 16);
    int outlen1 = 0;
    if (EVP_EncryptUpdate(ctx, out.data(), &outlen1, plaintext.data(), (int)plaintext.size()) != 1)
        throw std::runtime_error("EncryptUpdate failed");
    int outlen2 = 0;
    if (EVP_EncryptFinal_ex(ctx, out.data() + outlen1, &outlen2) != 1)
        throw std::runtime_error("EncryptFinal failed");

    out.resize(outlen1 + outlen2);

    tag_out.resize(16);
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, 16, tag_out.data()) != 1)
        throw std::runtime_error("GCM get tag failed");

    EVP_CIPHER_CTX_free(ctx);
    return out;
}

static std::vector<unsigned char> aes_gcm_decrypt(const std::vector<unsigned char>& key32,
                                                  const std::vector<unsigned char>& iv,
                                                  const std::vector<unsigned char>& tag,
                                                  const std::vector<unsigned char>& ciphertext) {
    EVP_CIPHER_CTX* ctx = EVP_CIPHER_CTX_new();
    if (!ctx) throw std::runtime_error("EVP_CIPHER_CTX_new failed");

    if (EVP_DecryptInit_ex(ctx, EVP_aes_256_gcm(), nullptr, nullptr, nullptr) != 1)
        throw std::runtime_error("DecryptInit_ex failed");
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_IVLEN, (int)iv.size(), nullptr) != 1)
        throw std::runtime_error("GCM set IV len failed");
    if (EVP_DecryptInit_ex(ctx, nullptr, nullptr, key32.data(), iv.data()) != 1)
        throw std::runtime_error("DecryptInit_ex key/iv failed");

    std::vector<unsigned char> out(ciphertext.size() + 16);
    int outlen1 = 0;
    if (EVP_DecryptUpdate(ctx, out.data(), &outlen1, ciphertext.data(), (int)ciphertext.size()) != 1)
        throw std::runtime_error("DecryptUpdate failed");
    if (EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, (int)tag.size(), (void*)tag.data()) != 1)
        throw std::runtime_error("GCM set tag failed");

    int outlen2 = 0;
    if (EVP_DecryptFinal_ex(ctx, out.data() + outlen1, &outlen2) != 1) {
        EVP_CIPHER_CTX_free(ctx);
        throw std::runtime_error("DecryptFinal failed (auth tag mismatch)");
    }
    out.resize(outlen1 + outlen2);
    EVP_CIPHER_CTX_free(ctx);
    return out;
}

static RSA* load_rsa_pub_from_pem(const std::string& pem) {
    BIO* bio = BIO_new_mem_buf(pem.data(), (int)pem.size());
    if (!bio) return nullptr;
    RSA* rsa = PEM_read_bio_RSA_PUBKEY(bio, nullptr, nullptr, nullptr); // tries SPKI
    if (!rsa) {
        BIO_free(bio);
        BIO* bio2 = BIO_new_mem_buf(pem.data(), (int)pem.size());
        rsa = PEM_read_bio_RSAPublicKey(bio2, nullptr, nullptr, nullptr); // PKCS#1
        BIO_free(bio2);
    } else {
        BIO_free(bio);
    }
    return rsa;
}

static std::vector<unsigned char> rsa_oaep_sha256_encrypt(RSA* rsa, const std::vector<unsigned char>& data) {
    std::vector<unsigned char> out((size_t)RSA_size(rsa));
    int ret = RSA_public_encrypt((int)data.size(), data.data(), out.data(), rsa,
                                 RSA_PKCS1_OAEP_PADDING);
    if (ret <= 0) throw std::runtime_error("RSA_public_encrypt failed");
    out.resize((size_t)ret);
    return out;
}

static std::string hmac_sha256_b64url(const std::string& key, const std::string& msg) {
    unsigned int len = 0;
    unsigned char mac[EVP_MAX_MD_SIZE];
    HMAC(EVP_sha256(),
         reinterpret_cast<const unsigned char*>(key.data()), (int)key.size(),
         reinterpret_cast<const unsigned char*>(msg.data()), (int)msg.size(),
         mac, &len);
    return b64url_from_bytes(mac, len);
}

// -------------------------- HTTP: fetch public key --------------------------

static std::string http_get_pubkey(asio::io_context& ioc, const std::string& host, const std::string& port) {
    tcp::resolver resolver(ioc);
    beast::tcp_stream stream(ioc);
    auto const results = resolver.resolve(host, port);
    stream.connect(results);

    http::request<http::string_body> req{http::verb::get, "/pubkey", 11};
    req.set(http::field::host, host);
    req.set(http::field::user_agent, "cppclient/1.0");
    http::write(stream, req);

    beast::flat_buffer buffer;
    http::response<http::string_body> res;
    http::read(stream, buffer, res);

    beast::error_code ec;
    stream.socket().shutdown(tcp::socket::shutdown_both, ec);

    if (res.result() != http::status::ok)
        throw std::runtime_error("HTTP /pubkey failed: " + std::to_string((int)res.result()));

    auto body = res.body();
    auto j = json::parse(body);
    if (!j.contains("bundle")) throw std::runtime_error("pubkey bundle missing");
    auto bundle = j["bundle"];
    if (!bundle.contains("transportPublicKey")) throw std::runtime_error("transportPublicKey missing");
    return bundle["transportPublicKey"].get<std::string>();
}

// -------------------------- WebSocket encrypted channel --------------------------

class SecureWSClient {
public:
    SecureWSClient(asio::io_context& ioc,
                   const std::string& host, const std::string& port, const std::string& target,
                   const std::string& license)
        : ioc_(ioc), resolver_(ioc), ws_(ioc), host_(host), port_(port), target_(target),
          licenseKey_(license) {
        symKey_.resize(32);
        RAND_bytes(symKey_.data(), (int)symKey_.size());
    }

    void setServerPublicKeyPEM(const std::string& pem) {
        rsa_.reset(load_rsa_pub_from_pem(pem));
        if (!rsa_) throw std::runtime_error("Failed to parse server RSA public key");
    }

    void connectAndRun() {
        // Resolve/connect
        auto results = resolver_.resolve(host_, port_);
        auto ep = asio::connect(ws_.next_layer(), results);
        host_ += ":" + std::to_string(ep.port());

        // WS handshake
        ws_.handshake(host_, target_);
        std::cout << "[ws] connected\n";

        // Send key_exchange (unencrypted)
        std::vector<unsigned char> enc = rsa_oaep_sha256_encrypt(rsa_.get(), symKey_);
        json jke = { {"type","key_exchange"}, {"encKey", b64url_from_bytes(enc.data(), enc.size())} };
        ws_.write(asio::buffer(jke.dump()));

        // Expect encrypted key_ok
        json msg = readEncrypted();
        if (msg.value("type","") != "key_ok") throw std::runtime_error("Expected key_ok");
        std::cout << "[ws] key_ok\n";

        // Send auth
        clientId_ = uuid_v4();
        json jauth = {
            {"type","auth"},
            {"licenseKey", licenseKey_},
            {"clientId", clientId_},
            {"clientLogPub", "NA"} // optional here
        };
        writeEncrypted(jauth);

        json ares = readEncrypted();
        if (ares.value("type","") != "auth_ok") {
            throw std::runtime_error("Auth failed: " + ares.dump());
        }
        jwt_ = ares.value("token", "");
        if (jwt_.empty()) throw std::runtime_error("No JWT received");
        std::cout << "[auth] ok, jwt length=" << jwt_.size() << "\n";

        // Launch loops
        running_ = true;
        reader_ = std::thread([this]{ this->readerLoop(); });
        hb_ = std::thread([this]{ this->heartbeatLoop(); });
        rnd_ = std::thread([this]{ this->randomCheckLoop(); });

        // Keep main thread alive until Ctrl+C or error
        reader_.join(); // If reader exits, we stop others
        running_ = false;
        if (hb_.joinable()) hb_.join();
        if (rnd_.joinable()) rnd_.join();
    }

private:
    // AES-GCM helpers with JSON packets
    json readEncrypted() {
        beast::flat_buffer buffer;
        ws_.read(buffer);
        std::string payload = beast::buffers_to_string(buffer.data());
        // Expect JSON packet { iv, tag, data }
        json pkt = json::parse(payload);
        std::vector<unsigned char> iv = b64_to_vec(pkt.value("iv", ""));
        std::vector<unsigned char> tag = b64_to_vec(pkt.value("tag", ""));
        std::vector<unsigned char> data = b64_to_vec(pkt.value("data", ""));
        std::vector<unsigned char> plain = aes_gcm_decrypt(symKey_, iv, tag, data);
        return json::parse(std::string((char*)plain.data(), plain.size()));
    }

    void writeEncrypted(const json& j) {
        std::string s = j.dump();
        std::vector<unsigned char> pt(s.begin(), s.end());
        std::vector<unsigned char> iv, tag;
        std::vector<unsigned char> ct = aes_gcm_encrypt(symKey_, pt, iv, tag);
        json pkt = {
            {"iv",  base64(iv)},
            {"tag", base64(tag)},
            {"data",base64(ct)}
        };
        ws_.write(asio::buffer(pkt.dump()));
    }

    void readerLoop() {
        try {
            while (running_) {
                json msg = readEncrypted();
                std::string type = msg.value("type", "");
                if (type == "hb_ack") {
                    // ignore
                } else if (type == "random_check_ack") {
                    std::string kind = msg.value("kind", "");
                    if (kind == "hmac") {
                        // Server sent a nonce; reply with hmac_proof using JWT key
                        std::string nonce = msg.value("nonce", "");
                        std::string mac = hmac_sha256_b64url(jwt_, nonce);
                        json proof = { {"type","hmac_proof"}, {"nonce", nonce}, {"mac", mac} };
                        writeEncrypted(proof);
                    }
                } else if (type == "challenge") {
                    handleChallenge(msg);
                } else if (type == "challenge_ok") {
                    std::cout << "[challenge] ok\n";
                } else if (type == "auth_fail") {
                    std::cerr << "[server] auth_fail: " << msg.dump() << "\n";
                    break;
                } else if (type == "err") {
                    std::cerr << "[server] err: " << msg.dump() << "\n";
                } else if (type == "log_ack") {
                    // ignore
                } else {
                    std::cout << "[recv] " << msg.dump() << "\n";
                }
            }
        } catch (const std::exception& e) {
            std::cerr << "[reader] error: " << e.what() << "\n";
        }
    }

    void heartbeatLoop() {
        try {
            while (running_) {
                json hb = { {"type","hb"}, {"t", (long long)std::time(nullptr)} };
                writeEncrypted(hb);
                std::this_thread::sleep_for(std::chrono::seconds(5));
            }
        } catch (const std::exception& e) {
            std::cerr << "[hb] error: " << e.what() << "\n";
        }
    }

    void randomCheckLoop() {
        try {
            std::mt19937 rng{std::random_device{}()};
            std::uniform_int_distribution<int> delay(6, 14);
            std::uniform_int_distribution<int> kindd(0, 3);
            while (running_) {
                std::this_thread::sleep_for(std::chrono::seconds(delay(rng)));
                int k = kindd(rng);
                std::string kind = (k==0 ? "ping" : k==1 ? "time" : k==2 ? "nonce" : "hmac");
                json rc = { {"type","random_check"}, {"kind", kind} };
                writeEncrypted(rc);
            }
        } catch (const std::exception& e) {
            std::cerr << "[rnd] error: " << e.what() << "\n";
        }
    }

    void handleChallenge(const json& ch) {
        std::string id = ch.value("id", "");
        std::string ctype = ch.value("ctype", "");
        json payload = ch.value("payload", json::object());
        long long deadline = ch.value("deadline", 0);

        if (ctype == "math") {
            int a = payload.value("a", 0);
            int b = payload.value("b", 0);
            std::string op = payload.value("op", "+");
            long long ans = 0;
            if (op == "+") ans = (long long)a + (long long)b;
            else { /* extend if server adds ops */ }
            json resp = { {"type","challenge_resp"}, {"id", id}, {"answer", ans} };
            writeEncrypted(resp);
        } else if (ctype == "hmac") {
            // The server expects HMAC-SHA256 with static secret "server" on payload.nonce
            std::string nonce = payload.value("nonce", "");
            std::string mac = hmac_sha256_b64url(std::string("server"), nonce);
            json resp = { {"type","challenge_resp"}, {"id", id}, {"answer", mac} };
            writeEncrypted(resp);
        } else {
            // Unknown challenge; fail gracefully
            json resp = { {"type","challenge_resp"}, {"id", id}, {"answer", ""} };
            writeEncrypted(resp);
        }
    }

private:
    asio::io_context& ioc_;
    tcp::resolver resolver_;
    ws::stream<tcp::socket> ws_;
    std::string host_, port_, target_;
    std::string licenseKey_;
    std::unique_ptr<RSA, decltype(&RSA_free)> rsa_{nullptr, &RSA_free};
    std::vector<unsigned char> symKey_;
    std::string clientId_;
    std::string jwt_;
    std::atomic<bool> running_{false};
    std::thread reader_, hb_, rnd_;
};

// -------------------------- main --------------------------

int main(int argc, char** argv) {
    try {
        std::string host = "localhost";
        std::string port = "8080";
        std::string ws_path = "/ws";
        std::string license = "DEMO-LIC-0001";

        if (argc > 1) license = argv[1];        // allow override: ./cppclient LICENSE
        if (argc > 3) { host = argv[2]; port = argv[3]; }
        if (argc > 4) ws_path = argv[4];

        asio::io_context ioc;

        // 1) Fetch server public key
        std::string pubpem = http_get_pubkey(ioc, host, port);
        std::cout << "[http] received public key (" << pubpem.size() << " bytes)\n";

        // 2) Connect to websocket and run secure session
        SecureWSClient client(ioc, host, port, ws_path, license);
        client.setServerPublicKeyPEM(pubpem);
        client.connectAndRun();

        return 0;
    } catch (const std::exception& e) {
        std::cerr << "[fatal] " << e.what() << "\n";
        return 1;
    }
}
