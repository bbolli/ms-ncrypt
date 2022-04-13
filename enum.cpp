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
    }
    ~Key() noexcept {
        NCryptFreeObject(key);
        X509_free(certificate);
    }
    NCRYPT_KEY_HANDLE get() const noexcept { return key; }

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
    X509* certificate{};
};


int WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    std::wstring msg;

    auto providers = Providers{};
    msg.append(L"Storage providers:\n");
    for (auto const& p : providers.get())
        fmt::format_to(std::back_inserter(msg), L"{}\n", p.pszName);
    msg.append(L"\n");

    auto keys = Keys{MS_SMART_CARD_KEY_STORAGE_PROVIDER};
    fmt::format_to(std::back_inserter(msg), L"Keys: {}\n", keys.get().size());
    for (auto k : keys.get()) {
        Key key(keys.provider(), k);
        if (auto x509 = key.x509()) {
            auto subj = X509_get_subject_name(x509);
            char sn[1024];
            if (X509_NAME_oneline(subj, sn, sizeof sn)) {
                wchar_t wsn[1024];
                MultiByteToWideChar(CP_ACP, 0, sn, int(strlen(sn) + 1), wsn, 1024);
                fmt::format_to(std::back_inserter(msg), L"{}: {}, {}\n", wsn,
                               k->pszName, k->pszAlgid);
            }
        }
    }

    MessageBoxW(NULL, msg.data(), L"Providers and keys", MB_OK);
    return 0;
}
