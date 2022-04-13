#define WIN32_MEAN_AND_LEAN
#include <Windows.h>
#include <ncrypt.h>

#include <limits>
#include <string>
#include <vector>
#include <span>

#include <fmt/format.h>
#include <fmt/xchar.h>

#include <openssl/asn1.h>
#include <openssl/x509.h>


void error_check(HRESULT res, char const* call) {
    if (res == ERROR_SUCCESS)
        return;
    fmt::print("Error {:#08x} in {}\n", static_cast<ULONG>(res), call);
    exit(1);
}


#define CHECK(call) error_check(call, #call)


struct Providers {
    Providers() noexcept {
        DWORD n;
        CHECK(NCryptEnumStorageProviders(&n, &pl, 0));
        providers = { pl, static_cast<size_t>(n) };
    }
    ~Providers() noexcept {
        NCryptFreeBuffer(pl);
    }

    using type = std::span<NCryptProviderName>;

    type get() const { return providers; }
private:
    type providers{};
    NCryptProviderName* pl{};
};


struct Keys {
    Keys(LPCWSTR providerName) noexcept {
        CHECK(NCryptOpenStorageProvider(&hProv, providerName, 0));
        void* state{};
        NCryptKeyName* kn;
        while (NCryptEnumKeys(hProv, nullptr, &kn, &state, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS)
            keys.emplace_back(kn);
        NCryptFreeBuffer(state);
    }
    ~Keys() noexcept {
        for (auto k : keys)
            NCryptFreeBuffer(k);
        if (hProv)
            NCryptFreeObject(hProv);
    }

    using type = std::vector<NCryptKeyName*>;

    type const& get() const { return keys; }
    NCRYPT_PROV_HANDLE provider() const { return hProv; }
private:
    NCRYPT_PROV_HANDLE hProv{};
    type keys;
};


struct Key {
    Key(NCRYPT_PROV_HANDLE hProv, NCryptKeyName* keyName) noexcept {
        CHECK(NCryptOpenKey(hProv, &key, keyName->pszName,
                            keyName->dwLegacyKeySpec, 0));
        DWORD size{};
        NCryptGetProperty(key, NCRYPT_READER_PROPERTY, nullptr, 0, &size, 0);
        reader.resize(size);
        if (size) {
            CHECK(NCryptGetProperty(key, NCRYPT_READER_PROPERTY,
                                    (PBYTE)reader.data(), size, &size, 0));
            // the reader name is NUL-padded; trim it
            reader.erase(reader.find(L'\0'));
        }
    }
    ~Key() noexcept {
        NCryptFreeObject(key);
        X509_free(certificate);
    }
    NCRYPT_KEY_HANDLE get() const noexcept { return key; }
    std::wstring_view rdr() const noexcept { return reader; }

    std::vector<BYTE> read() noexcept {
        DWORD size{};
        NCryptGetProperty(key, NCRYPT_CERTIFICATE_PROPERTY, nullptr, 0, &size, 0);
        auto buf = std::vector<BYTE>(size);
        if (size) {
            CHECK(NCryptGetProperty(key, NCRYPT_CERTIFICATE_PROPERTY,
                                    buf.data(), size, &size, 0));
        }
        return buf;
    }

    X509* x509() noexcept {
        if (certificate)
            return certificate;
        auto cert = read();
        if (auto len = cert.size(); len && len < std::numeric_limits<long>::max()) {
            const unsigned char* in = cert.data();
            certificate = d2i_X509(nullptr, &in, static_cast<long>(len));
        } else {
            certificate = nullptr;
        }
        return certificate;
    }

private:
    NCRYPT_KEY_HANDLE key{};
    std::wstring reader;
    X509* certificate{};
};


int WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
#if 0
    auto providers = Providers{};
    fmt::print("Storage providers:\n");
    for (auto const& p : providers.get())
        fmt::print(L"{}\n", p.pszName);
    fmt::print("\n");
#endif
    auto keys = Keys{MS_SMART_CARD_KEY_STORAGE_PROVIDER};
    fmt::print("# Keys: {}\n", keys.get().size());
    for (auto k : keys.get()) {
        Key key(keys.provider(), k);
        fmt::print(L"name: {}, {}, {}\n", k->pszName, k->pszAlgid, key.rdr());
        if (auto x509 = key.x509()) {
            auto subj = X509_get_subject_name(x509);
            char sn[1024];
            if (X509_NAME_oneline(subj, sn, sizeof sn)) {
                fmt::print("    {}\n", sn);
            } else {
                fmt::print("    X509_NAME_oneline() failed\n");
            }
        } else {
            fmt::print("    certificate is empty\n");
        }
    }

    return 0;
}
