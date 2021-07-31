#define WIN32_MEAN_AND_LEAN
#include <Windows.h>
#include <ncrypt.h>

#include <string>
#include <vector>
#include <gsl/span>

#include <openssl/asn1.h>
#include <openssl/x509.h>


struct Providers {
    Providers() noexcept {
        DWORD n;
        if (NCryptEnumStorageProviders(&n, &pl, 0) == ERROR_SUCCESS)
            providers = { pl, static_cast<size_t>(n) };
    }
    ~Providers() noexcept {
        NCryptFreeBuffer(pl);
    }

    using type = gsl::span<NCryptProviderName>;

    type get() const { return providers; }
private:
    type providers{};
    NCryptProviderName* pl{};
};


struct Keys {
    Keys(LPCWSTR providerName) noexcept {
        if (NCryptOpenStorageProvider(&hProv, providerName, 0) != ERROR_SUCCESS)
            return;
        NCryptKeyName* kn;
        while (NCryptEnumKeys(hProv, nullptr, &kn, &state, NCRYPT_SILENT_FLAG) == ERROR_SUCCESS)
            keys.emplace_back(kn);
    }
    ~Keys() noexcept {
        if (hProv)
            NCryptFreeObject(hProv);
        if (state)
            NCryptFreeBuffer(state);
        for (auto k : keys)
            NCryptFreeBuffer(k);
    }

    using type = std::vector<NCryptKeyName*>;

    type const& get() const { return keys; }
    NCRYPT_PROV_HANDLE provider() const { return hProv; }    
private:
    NCRYPT_PROV_HANDLE hProv{};
    void* state{};
    type keys;
};

struct Key {
    Key(NCRYPT_PROV_HANDLE hProv, NCryptKeyName* keyName) noexcept {
        NCryptOpenKey(hProv, &key, keyName->pszName, keyName->dwLegacyKeySpec, 0);
    }
    ~Key() noexcept {
        NCryptFreeObject(key);
    }
    NCRYPT_KEY_HANDLE get() const noexcept { return key; }

    std::basic_string<BYTE> certificate() noexcept {
        DWORD size{};
        NCryptGetProperty(key, NCRYPT_CERTIFICATE_PROPERTY, nullptr, 0, &size, 0);
        auto buf = std::basic_string<BYTE>();
        if (size) {
            buf.resize(size, '\0');
            NCryptGetProperty(key, NCRYPT_CERTIFICATE_PROPERTY, buf.data(), buf.size(), &size, 0);
        }
        return buf;
    }
private:
    NCRYPT_KEY_HANDLE key{};
};


int WinMain(HINSTANCE, HINSTANCE, LPSTR, int) {
    std::wstring msg;
    /*
    auto providers = Providers{};
    msg.append(L"Storage providers:\n");
    for (auto const& p : providers.get())
        msg.append(p.pszName).append(L"\n");
    msg.append(L"\n");
    */
    msg.append(L"Keys:\n");
    Keys keys(MS_SMART_CARD_KEY_STORAGE_PROVIDER);
    for (auto k : keys.get()) {
        Key key(keys.provider(), k);
        auto cert = key.certificate();
        const unsigned char* in = cert.data();
        long len = cert.size();
        if (len) {
            auto x509 = d2i_X509(nullptr, &in, len);
            auto subj = X509_get_subject_name(x509);
            char sn[1024];
            auto ne = X509_NAME_oneline(subj, sn, sizeof sn);
            MessageBoxA(NULL, ne, "Subject name", MB_OK);
            X509_NAME_free(subj);
            X509_free(x509);
            //return 0;
            msg.append(k->pszName).append(L", ").append(k->pszAlgid)
                // .append(L" ").append(wsn)
                .append(L", ").append(std::to_wstring(len)).append(L" bytes\n");
        }
    }

    MessageBoxW(NULL, msg.data(), L"Providers and keys", MB_OK);
    return 0;
}
