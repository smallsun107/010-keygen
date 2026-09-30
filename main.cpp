#include <cstdint>
#include <cstdio>
#include <cstdlib>
#include <cstring>
#include <string>
#include <iostream>

// -----------------------------------------------------------------------------
// 验证方法: 模拟执行 (Unicorn)
// -----------------------------------------------------------------------------
// 为确认本文件的 hash / 字段解码与目标二进制完全一致, 从 IDA 取出真实机器码,
// 以原始虚拟地址在 Unicorn 中模拟执行, 再与本地实现逐组比对。
//
//   1) 取字节 (IDA):
//        sub_10019C330  hash     256  字节 @ 0x10019C330
//        sub_10019C610  AD76      32  字节 @ 0x10019C610
//        sub_10019C630  C5B       64  字节 @ 0x10019C630
//        dword_100B8D750  S 表  1024  字节 @ 0x100B8D750
//
//   2) 映射 (必须用原始地址, 才能让函数内的 RIP 相对寻址命中):
//        Uc(UC_ARCH_X86, UC_MODE_64)
//        code page 0x10019C000 (0x1000)  <- hash 机器码
//        sbox page 0x100B8D000 (0x1000)  <- S 表
//        name buf  0x20000000 (0x1000)
//        stack     0x30000000 (0x20000); 栈顶压入 sentinel 当作返回地址
//
//   3) 外部调用 (没有 libc, 用 UC_HOOK_CODE 在 call 指令处拦截并手工返回):
//        0x10019C34C  call _strlen    : 读 RDI 求串长 -> RAX, 跳过 call (RIP += 5)
//        0x10019C3C9  call ___toupper : 读 EDI 做 ASCII 大写 -> RAX, RIP += 5
//        其它地址只判断是否等于 sentinel, 命中即 emu_stop
//
//   4) 传参 (SysV x64): RDI=name, ESI=flag, EDX=a3, ECX=a4; emu_start 后取 RAX。
//      注意: 必须先压 sentinel 再 run, 否则函数 ret 后无处可去。
//
// 结果: 45 组 name/salt 与本地 calc_hash 全等; AD76/C5B 逆变换经真实函数来回
//       解码一致; 随机用户名「生成 -> 真实解码 -> 真实 hash」回环全部通过。
// -----------------------------------------------------------------------------

// -----------------------------------------------------------------------------
// S 表: IDA dword_100B8D750 原样导出 (256 x uint32)
// -----------------------------------------------------------------------------
static const uint32_t S[256] = {
    0x39CB44B8, 0x23754F67, 0x5F017211, 0x3EBB24DA, 0x351707C6, 0x63F9774B,
    0x17827288, 0x0FE74821, 0x5B5F670F, 0x48315AE8, 0x785B7769, 0x2B7A1547,
    0x38D11292, 0x42A11B32, 0x35332244, 0x77437B60, 0x1EAB3B10, 0x53810000,
    0x1D0212AE, 0x6F0377A8, 0x43C03092, 0x2D3C0A8E, 0x62950CBF, 0x30F06FFA,
    0x34F710E0, 0x28F417FB, 0x350D2F95, 0x5A361D5A, 0x15CC060B, 0x0AFD13CC,
    0x28603BCF, 0x3371066B, 0x30CD14E4, 0x175D3A67, 0x6DD66A13, 0x2D3409F9,
    0x581E7B82, 0x76526B99, 0x5C8D5188, 0x2C857971, 0x15F51FC0, 0x68CC0D11,
    0x49F55E5C, 0x275E4364, 0x2D1E0DBC, 0x4CEE7CE3, 0x32555840, 0x112E2E08,
    0x6978065A, 0x72921406, 0x314578E7, 0x175621B7, 0x40771DBF, 0x3FC238D6,
    0x4A31128A, 0x2DAD036E, 0x41A069D6, 0x25400192, 0x00DD4667, 0x6AFC1F4F,
    0x571040CE, 0x62FE66DF, 0x41DB4B3E, 0x3582231F, 0x55F6079A, 0x1CA70644,
    0x1B1643D2, 0x3F7228C9, 0x5F141070, 0x3E1474AB, 0x444B256E, 0x537050D9,
    0x0F42094B, 0x2FD820E6, 0x778B2E5E, 0x71176D02, 0x7FEA7A69, 0x5BB54628,
    0x19BA6C71, 0x39763A99, 0x178D54CD, 0x01246E88, 0x3313537E, 0x2B8E2D17,
    0x2A3D10BE, 0x59D10582, 0x37A163DB, 0x30D6489A, 0x6A215C46, 0x0E1C7A76,
    0x1FC760E7, 0x79B80C65, 0x27F459B4, 0x799A7326, 0x50BA1782, 0x2A116D5C,
    0x63866E1B, 0x3F920E3C, 0x55023490, 0x55B56089, 0x2C391FD1, 0x2F8035C2,
    0x64FD2B7A, 0x4CE8759A, 0x518504F0, 0x799501A8, 0x3F5B2CAD, 0x38E60160,
    0x637641D8, 0x33352A42, 0x51A22C19, 0x085C5851, 0x032917AB, 0x2B770AC7,
    0x30AC77B3, 0x2BEC1907, 0x035202D0, 0x0FA933D3, 0x61255DF3, 0x22AD06BF,
    0x58B86971, 0x5FCA0DE5, 0x700D6456, 0x56A973DB, 0x5AB759FD, 0x330E0BE2,
    0x5B3C0DDD, 0x495D3C60, 0x53BD59A6, 0x4C5E6D91, 0x49D9318D, 0x103D5079,
    0x61CE42E3, 0x7ED5121D, 0x14E160ED, 0x212D4EF2, 0x270133F0, 0x62435A96,
    0x1FA75E8B, 0x6F092FBE, 0x4A000D49, 0x57AE1C70, 0x004E2477, 0x561E7E72,
    0x468C0033, 0x5DCC2402, 0x78507AC6, 0x58AF24C7, 0x0DF62D34, 0x358A4708,
    0x3CFB1E11, 0x2B71451C, 0x77A75295, 0x56890721, 0x0FEF75F3, 0x120F24F1,
    0x01990AE7, 0x339C4452, 0x27A15B8E, 0x0BA7276D, 0x60DC1B7B, 0x4F4B7F82,
    0x67DB7007, 0x4F4A57D9, 0x621252E8, 0x20532CFC, 0x6A390306, 0x18800423,
    0x19F3778A, 0x462316F0, 0x56AE0937, 0x43C2675C, 0x65CA45FD, 0x0D604FF2,
    0x0BFD22CB, 0x3AFE643B, 0x3BF67FA6, 0x44623579, 0x184031F8, 0x32174F97,
    0x4C6A092A, 0x5FB50261, 0x01650174, 0x33634AF1, 0x712D18F4, 0x6E997169,
    0x5DAB7AFE, 0x7C2B2EE8, 0x6EDB75B4, 0x5F836FB6, 0x3C2A6DD6, 0x292D05C2,
    0x052244DB, 0x149A5F4F, 0x5D486540, 0x331D15EA, 0x4F456920, 0x483A699F,
    0x3B450F05, 0x3B207C6C, 0x749D70FE, 0x417461F6, 0x62B031F1, 0x2750577B,
    0x29131533, 0x588C3808, 0x1AEF3456, 0x0F3C00EC, 0x7DA74742, 0x4B797A6C,
    0x5EBB3287, 0x786558B8, 0x00ED4FF2, 0x6269691E, 0x24A2255F, 0x62C11F7E,
    0x2F8A7DCD, 0x643B17FE, 0x778318B8, 0x253B60FE, 0x34BB63A3, 0x5B03214F,
    0x5F1571F4, 0x1A316E9F, 0x7ACF2704, 0x28896838, 0x18614677, 0x1BF569EB,
    0x0BA85EC9, 0x6ACA6B46, 0x1E43422A, 0x514D5F0E, 0x413E018C, 0x307626E9,
    0x01ED1DFA, 0x49F46F5A, 0x461B642B, 0x7D7007F2, 0x13652657, 0x6B160BC5,
    0x65E04849, 0x1F526E1C, 0x5A0251B6, 0x2BD73F69, 0x2DBF7ACD, 0x51E63E80,
    0x5CF2670F, 0x21CD0A03, 0x5CFF0261, 0x33AE061E, 0x3BB6345F, 0x5D814A75,
    0x257B5DF4, 0x0A5C2C5B, 0x16A45527, 0x16F23945,
};

// -----------------------------------------------------------------------------
// 基础工具
// -----------------------------------------------------------------------------
// 目标使用 __toupper() (C locale): 仅 ASCII a-z 转大写, >=0x80 不变
static uint8_t ascii_upper(uint8_t c) {
    return (c >= 'a' && c <= 'z') ? (uint8_t)(c - 32) : c;
}

// 字符 -> 数值 (sub_100106550 内联的转换表, 容忍 O/l 等易混字符)
static uint8_t hexval(uint8_t c) {
    if (c >= '0' && c <= '9') return (uint8_t)(c - '0');
    if (c == 'O' || c == 'o') return 0;
    if (c == 'l') return 1;
    if (c >= 'a' && c <= 'z') return (uint8_t)(c - 'a' + 10);
    if (c >= 'A' && c <= 'Z') return (uint8_t)(c - 'A' + 10);
    return 0;
}

// -----------------------------------------------------------------------------
// AD76: sub_10019C610   y = ((x ^ 0x18) + 0x3D) ^ 0xA7
// -----------------------------------------------------------------------------
static uint8_t ad76(uint8_t x) {
    return (uint8_t)(((x ^ 0x18) + 0x3D) ^ 0xA7);
}
static uint8_t ad76_inv(uint8_t y) {
    return (uint8_t)((((y ^ 0xA7) - 0x3D)) ^ 0x18);
}

// -----------------------------------------------------------------------------
// C5B: sub_10019C630   v = ((x ^ 0x7892) + 0x4D30) ^ 0x3421 ; v % 11 ? 0 : v/11
// -----------------------------------------------------------------------------
static uint16_t c5b(uint16_t x) {
    uint32_t v = (((uint32_t)(x ^ 0x7892u) + 0x4D30u) ^ 0x3421u) & 0xFFFFu;
    return (v % 11u == 0u) ? (uint16_t)(v / 11u) : (uint16_t)0;
}
static uint16_t c5b_inv(uint16_t q) {
    uint32_t v = ((uint32_t)q * 11u) & 0xFFFFu;
    return (uint16_t)((((v ^ 0x3421u) - 0x4D30u) ^ 0x7892u) & 0xFFFFu);
}

// -----------------------------------------------------------------------------
// hash: sub_10019C330
//   name  : UTF-8 字节串 (QString::toUtf8)
//   flag  : 0x9C 路径恒 1 ; 0xFC 路径 0
//   a3    : 版本相关 (版本>=2 时为 0)
//   a4    : 盐 [1,1000]
// -----------------------------------------------------------------------------
static uint32_t calc_hash(const std::string& name, int flag, uint8_t a3, uint8_t a4) {
    if (name.empty()) return 0;
    uint8_t g1 = 0;                       // 游标1, 步进 19
    uint8_t g2 = (uint8_t)(15 * a4);      // 游标2, 步进 13, 起点由盐定
    uint8_t g3 = 0;                       // 游标3, 步进 7
    uint8_t g4 = (uint8_t)(17 * a3);      // 游标4, 步进 9,  起点由版本定
    uint32_t acc = 0;
    for (unsigned char raw : name) {
        uint8_t c = ascii_upper(raw);
        uint32_t t = acc + S[c];
        uint32_t v18;
        uint8_t v19, v20;
        if (flag) { v18 = S[(uint8_t)(c + 13)] ^ t; v19 = (uint8_t)(c + 47); v20 = g1; }
        else      { v18 = S[(uint8_t)(c + 63)] ^ t; v19 = (uint8_t)(c + 23); v20 = g3; }
        // 先取表值后步进
        acc = S[g2] + S[g4] + S[v20] + S[v19] * v18;   // uint32 自然截断
        g4 = (uint8_t)(g4 + 9);
        g2 = (uint8_t)(g2 + 13);
        g1 = (uint8_t)(g1 + 19);
        g3 = (uint8_t)(g3 + 7);
    }
    return acc;
}

// -----------------------------------------------------------------------------
// license 解码: sub_100106550  ->  b0..b7 (四段) / b0..b9 (五段)
// -----------------------------------------------------------------------------
struct Decoded {
    bool ok = false;
    int nbytes = 0;
    uint8_t b[10] = {0};
};

static Decoded decode_license(const std::string& lic) {
    Decoded d;
    size_t n = lic.size();
    if (n != 19 && n != 24) return d;
    if (lic[4] != '-' || lic[9] != '-' || lic[14] != '-') return d;
    if (n == 24 && lic[19] != '-') return d;
    // 每两个字符拼一字节, 横杠被跳过; 下标依次为 0,1,2,3,5,6,7,8,10,11,...
    static const int idx[10][2] = {
        {0,1},{2,3},{5,6},{7,8},{10,11},{12,13},{15,16},{17,18},{20,21},{22,23}
    };
    d.nbytes = (n == 24) ? 10 : 8;
    for (int i = 0; i < d.nbytes; ++i) {
        uint8_t hi = hexval((uint8_t)lic[idx[i][0]]);
        uint8_t lo = hexval((uint8_t)lic[idx[i][1]]);
        d.b[i] = (uint8_t)((hi << 4) | lo);
    }
    d.ok = true;
    return d;
}

// 指纹黑名单: byte_1005EEE00, 共 2 条表项
//   entry = [ name[0], name[1], b9, b8, b7, b6, b5, b4, b3, b2, b1, b0 ]
static const uint8_t kBlacklist[2][12] = {
    {0x43,0x4F,0x57,0xD6,0x30,0xE3,0xCA,0xB9,0xAC,0xAB,0xA1,0xC4}, // "CO" + d6 30 e3 ca b9 ac ab a1 c4 57
    {0x4A,0x55,0x59,0x2A,0x35,0xE2,0xC4,0x65,0xAC,0xD3,0xA4,0xCB}, // "JU" + 2a 35 e2 c4 65 ac d3 a4 cb 59
};

static bool hit_blacklist(const std::string& name, const Decoded& d) {
    if (name == "999" || name == "AnyOne") return true;
    if (name.size() <= 1) return false;
    for (const auto& e : kBlacklist) {
        if (ascii_upper((uint8_t)name[0]) != e[0]) continue;
        if (ascii_upper((uint8_t)name[1]) != e[1]) continue;
        if (d.b[9] == e[2] && d.b[8] == e[3] && d.b[7] == e[4] && d.b[6] == e[5] &&
            d.b[5] == e[6] && d.b[4] == e[7] && d.b[3] == e[8] && d.b[2] == e[9] &&
            d.b[1] == e[10] && d.b[0] == e[11])
            return true;
    }
    return false;
}

// -----------------------------------------------------------------------------
// 内层验证器 sub_100105E10
//   返回内层结果码: 45 激活 / 78 版本旧 / 147 试用 / 231 无效
// -----------------------------------------------------------------------------
static int inner_verify(const std::string& name, const std::string& lic) {
    Decoded d = decode_license(lic);
    if (!d.ok) return 231;
    if (hit_blacklist(name, d)) return 231;

    const uint8_t tn = d.b[3];
    if (tn == 0xFC) {                            // 试用版: 仍需 4 字节 hash 匹配
        uint32_t h = calc_hash(name, 0, 255, 1); // flag=0, 版本=255, 盐=1
        uint32_t stored = (uint32_t)d.b[4] | ((uint32_t)d.b[5] << 8) |
                          ((uint32_t)d.b[6] << 16) | ((uint32_t)d.b[7] << 24);
        if (h != stored) return 231;
        return 147;                              // 真实实现还要求试用期限解码 != 0
    }
    if (tn == 0x9C) {                           // 正式零售版
        uint8_t  ver  = ad76((uint8_t)(d.b[0] ^ d.b[6]));
        uint16_t salt = c5b((uint16_t)(((d.b[1] ^ d.b[7]) << 8) | (d.b[2] ^ d.b[5])));
        if (salt < 1 || salt > 1000 || ver == 0) return 231;
        uint8_t a3 = (ver < 2) ? ver : 0;
        uint32_t h = calc_hash(name, 1, a3, (uint8_t)salt);
        if (d.b[4] != (uint8_t)(h)        || d.b[5] != (uint8_t)(h >> 8) ||
            d.b[6] != (uint8_t)(h >> 16)  || d.b[7] != (uint8_t)(h >> 24))
            return 231;
        return (ver < 17) ? 78 : 45;
    }
    return 231;                                  // 其它类型暂不处理
}

// -----------------------------------------------------------------------------
// 生成 license
// -----------------------------------------------------------------------------
static std::string generate(const std::string& name, unsigned salt = 230, unsigned ver = 255) {
    if (salt < 1 || salt > 1000) salt = 230;
    if (ver  < 17 || ver  > 255) ver  = 255;

    uint32_t h = calc_hash(name, 1, 0, (uint8_t)salt);
    uint8_t b[8];
    b[3] = 0x9C;                                 // 正式零售版类型字节
    b[4] = (uint8_t)(h);
    b[5] = (uint8_t)(h >> 8);
    b[6] = (uint8_t)(h >> 16);
    b[7] = (uint8_t)(h >> 24);
    uint16_t v20 = c5b_inv((uint16_t)salt);
    b[2] = (uint8_t)(b[5] ^ (v20 & 0xFF));
    b[1] = (uint8_t)(b[7] ^ (v20 >> 8));
    b[0] = (uint8_t)(b[6] ^ ad76_inv((uint8_t)ver));

    char out[40];
    std::snprintf(out, sizeof(out), "%02X%02X-%02X%02X-%02X%02X-%02X%02X",
                  b[0], b[1], b[2], b[3], b[4], b[5], b[6], b[7]);
    return std::string(out);
}

// -----------------------------------------------------------------------------
// verify: 打印解码/校验过程
// -----------------------------------------------------------------------------
static void verify(const std::string& name, const std::string& lic) {
    Decoded d = decode_license(lic);

    std::cout << "Name     : " << name << "\n";
    std::cout << "License  : " << lic << "\n";
    std::cout << "--- Decode ---\n";
    if (!d.ok) {
        std::cout << "[-] bad format (expect 19 or 24 chars, dashes at 4/9/14/19)\n";
        std::cout << "[-] Invalid name or license\n";
        return;
    }
    std::cout << "bytes    : ";
    for (int i = 0; i < d.nbytes; ++i) std::printf("%02X ", d.b[i]);
    std::cout << "\n";
    std::cout << "type b3  : 0x" << std::hex << (unsigned)d.b[3] << std::dec;
    if (d.b[3] == 0x9C)      std::cout << " (retail)\n";
    else if (d.b[3] == 0xFC) std::cout << " (trial)\n";
    else if (d.b[3] == 0xAC) std::cout << " (enhanced)\n";
    else                     std::cout << " (unknown)\n";

    if (d.b[3] == 0x9C) {
        uint8_t  ver  = ad76((uint8_t)(d.b[0] ^ d.b[6]));
        uint16_t salt = c5b((uint16_t)(((d.b[1] ^ d.b[7]) << 8) | (d.b[2] ^ d.b[5])));
        uint8_t  a3   = (ver < 2) ? ver : 0;
        uint32_t h    = calc_hash(name, 1, a3, (uint8_t)salt);
        std::cout << "--- Fields ---\n";
        std::cout << "version  : " << (unsigned)ver << "  (AD76(b0^b6))\n";
        std::cout << "salt     : " << salt << "  (C5B((b1^b7)<<8|(b2^b5)))\n";
        std::cout << "hash     : 0x" << std::hex << h << std::dec << "  (calc_hash)\n";
        std::printf("stored   : %02X %02X %02X %02X  (b4..b7)\n", d.b[4], d.b[5], d.b[6], d.b[7]);
        std::cout << "checksum : " << (h == (uint32_t)(d.b[4] | (d.b[5] << 8) | (d.b[6] << 16) | ((uint32_t)d.b[7] << 24)) ? "match" : "MISMATCH") << "\n";
    }

    int inner = inner_verify(name, lic);
    std::cout << "--- Result ---\n";
    std::cout << "inner    : " << inner << "\n";
    switch (inner) {
        case 45:  std::cout << "[+] License activated. This license entitles you to Free Upgrades ...\n"; break;
        case 78:  std::cout << "[-] The license you entered is for an earlier version of this program\n"; break;
        case 147: std::cout << "[~] Trial license (period extended / already over)\n"; break;
        default:  std::cout << "[-] Invalid name or license\n"; break;
    }
}

int main(int argc, char* argv[]) {
    const char* program = std::strrchr(argv[0], '/');
    program = program ? program + 1 : argv[0];

    if (argc < 2) {
        std::cout << "Usage:\n";
        std::cout << "  " << program << " generate <name> [salt=1..1000] [version=17..255]\n";
        std::cout << "  " << program << " verify   <name> <license>\n";
        return 1;
    }

    std::string mode = argv[1];
    if (mode == "generate") {
        if (argc < 3) { std::cerr << "Please provide a name.\n"; return 1; }
        std::string name = argv[2];
        if (name == "999" || name == "AnyOne") {
            std::cerr << "Name is blacklisted (999 / AnyOne).\n";
            return 1;
        }
        unsigned salt = (argc >= 4) ? (unsigned)std::strtoul(argv[3], nullptr, 0) : 230u;
        unsigned ver  = (argc >= 5) ? (unsigned)std::strtoul(argv[4], nullptr, 0) : 255u;
        std::string lic = generate(name, salt, ver);
        std::cout << "Name    : " << name << "\n";
        std::cout << "Salt    : " << salt << "  Version: " << ver << "\n";
        std::cout << "License : " << lic << "\n";
        int code = inner_verify(name, lic);
        std::cout << "SelfTest: " << code << (code == 45 ? "  [OK]" : "  [FAIL]") << "\n";
    } else if (mode == "verify") {
        if (argc < 4) { std::cerr << "Please provide <name> <license>.\n"; return 1; }
        verify(argv[2], argv[3]);
    } else {
        std::cerr << "Unknown command: " << mode << "\n";
        return 1;
    }
    return 0;
}
