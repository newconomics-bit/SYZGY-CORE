#include "arith_uint256.h"
#include "uint256.h"
#include <cstdio>
#include <cmath>

int main()
{
    const uint256 mainLimit = uint256S("00000fffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    const uint256 regLimit  = uint256S("7fffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff");
    arith_uint256 ml = UintToArith256(mainLimit);
    arith_uint256 rl = UintToArith256(regLimit);

    printf("main   powLimit.GetCompact() = 0x%08x\n", ml.GetCompact());
    printf("regtest powLimit.GetCompact()= 0x%08x\n\n", rl.GetCompact());

    unsigned int cands[] = {0x1e00ffff, 0x1e0fffff, 0x1e0ffffe, 0x20000f, 0x207fffff};
    const char* nm[] = {"0x1e00ffff", "0x1e0fffff", "0x1e0ffffe", "0x20000f", "0x207fffff"};

    for (int i = 0; i < 5; i++) {
        bool n = false, o = false;
        arith_uint256 t;
        t.SetCompact(cands[i], &n, &o);
        const bool rangeOk = (!n && t != 0 && !o);
        const bool okMain = rangeOk && (t <= ml);
        const bool okReg  = rangeOk && (t <= rl);
        // E[hits] = 2^256 / target
        double log2t = 0;
        // compute log2 exactly via bit length
        for (int b = 255; b >= 0; --b) {
            const char c = t.GetHex()[63 - b / 4];
            const int v = (c <= '9') ? (c - '0') : (c - 'a' + 10);
            if (v & (1 << (3 - b % 4))) { log2t = b; break; }
        }
        double eh = pow(2.0, 256.0 - log2t);
        printf("%-11s target=%s  ~E[hits]=%12.4g  okMain=%s okReg=%s\n",
               nm[i], t.GetHex().c_str(), eh, okMain ? "YES" : "NO ", okReg ? "YES" : "NO ");
    }
    return 0;
}
