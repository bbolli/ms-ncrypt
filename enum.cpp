#include <fmt/format.h>
#include <fmt/xchar.h>

#include "ncrypt.hpp"

auto WinMain(HINSTANCE, HINSTANCE, LPSTR, int) -> int
{
#if 0
    auto providers = ncrypt::Providers{};
    fmt::print("Storage providers:\n");
    for (auto const& p : providers.get())
        fmt::print(L"{}\n", p.pszName);
    fmt::print("\n");
#endif

    auto keys = ncrypt::Keys{MS_SMART_CARD_KEY_STORAGE_PROVIDER};
    fmt::print("# Keys: {}\n", keys.get().size());
    for (auto k : keys.get()) {
        auto key = keys.key(k);
        fmt::print(L"name: {}, {}, {}\n", k->pszName, k->pszAlgid, key.rdr());
        if (auto const x509 = key.x509()) {
            auto const subj = X509_get_subject_name(x509);
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
