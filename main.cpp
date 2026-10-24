// ===========================================================================
//  Arma Reforger external overlay - single file build
//  ESP / wallhack, legit aimbot, skeleton, team check.
//  External: no injection, no driver, no BattlEye bypass needed.
// ===========================================================================

#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif
#ifndef NOMINMAX
#define NOMINMAX
#endif

#include <windows.h>
#include <tlhelp32.h>
#include <psapi.h>
#include <cstdint>
#include <cstring>
#include <cwchar>
#include <cstdio>
#include <cstdlib>
#include <cmath>
#include <string>
#include <vector>
#include <array>
#include <algorithm>
#include <unordered_map>

#pragma comment(lib, "user32.lib")
#pragma comment(lib, "gdi32.lib")
#pragma comment(lib, "psapi.lib")

#ifndef DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2
#define DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2 ((DPI_AWARENESS_CONTEXT)-4)
#endif
#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif

// ===========================================================================
//  math
// ===========================================================================
struct Vec2 { float x = 0.f, y = 0.f; };

struct Vec3 {
    float x = 0.f, y = 0.f, z = 0.f;
    Vec3() = default;
    Vec3(float X, float Y, float Z) : x(X), y(Y), z(Z) {}

    Vec3 operator-(const Vec3& o) const { return Vec3(x - o.x, y - o.y, z - o.z); }
    Vec3 operator+(const Vec3& o) const { return Vec3(x + o.x, y + o.y, z + o.z); }
    Vec3 operator*(float s)       const { return Vec3(x * s, y * s, z * s); }

    float Dot(const Vec3& o)      const { return x * o.x + y * o.y + z * o.z; }
    float Length()                const { return std::sqrt(x * x + y * y + z * z); }
    float Distance(const Vec3& o) const { return (*this - o).Length(); }

    bool IsFinite() const { return std::isfinite(x) && std::isfinite(y) && std::isfinite(z); }
    bool IsZero()   const { return x == 0.f && y == 0.f && z == 0.f; }
};

// ===========================================================================
//  memory
// ===========================================================================
class Memory {
public:
    HANDLE       handle     = nullptr;
    DWORD        pid        = 0;
    uintptr_t    moduleBase = 0;
    size_t       moduleSize = 0;
    std::wstring moduleName;

    // diagnostics
    std::wstring              lastError;
    std::vector<std::wstring> seenProcesses;

    bool Attach() {
        lastError.clear();
        seenProcesses.clear();

        std::vector<ProcHit> hits;
        if (!CollectGameProcesses(hits)) {
            lastError = L"CreateToolhelp32Snapshot failed.";
            return false;
        }
        for (const auto& h : hits) seenProcesses.push_back(h.exe);
        if (hits.empty()) {
            lastError = L"No process whose name starts with \"ArmaReforger\" is running.";
            return false;
        }

        // Prefer the process that owns a real window; push dedicated servers last.
        std::stable_sort(hits.begin(), hits.end(), [](const ProcHit& a, const ProcHit& b) {
            const bool sa = IsServer(a.exe), sb = IsServer(b.exe);
            if (sa != sb) return !sa;
            const bool wa = HasMainWindow(a.pid), wb = HasMainWindow(b.pid);
            return wa && !wb;
        });

        DWORD lastErr = 0;
        for (const auto& h : hits) {
            if (IsServer(h.exe)) continue;

            HANDLE ph = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, h.pid);
            if (!ph) ph = OpenProcess(PROCESS_VM_READ, FALSE, h.pid);
            if (!ph) { lastErr = GetLastError(); continue; }

            uintptr_t base = 0;
            size_t    size = 0;
            if (!FindModule(ph, h.pid, h.exe, base, size) && !FindMainModule(ph, base, size)) {
                lastErr = GetLastError();
                CloseHandle(ph);
                continue;
            }

            handle     = ph;
            pid        = h.pid;
            moduleBase = base;
            moduleSize = size;
            moduleName = h.exe;
            return true;
        }

        lastError = (lastErr == ERROR_ACCESS_DENIED)
            ? L"Process found, but OpenProcess was DENIED. Run this as Administrator."
            : L"Process found, but it could not be opened or read.";
        return false;
    }

    void Detach() {
        if (handle) { CloseHandle(handle); handle = nullptr; }
        pid = 0; moduleBase = 0; moduleSize = 0;
    }

    bool Alive() const {
        if (!handle) return false;
        DWORD code = 0;
        if (!GetExitCodeProcess(handle, &code)) return false;
        return code == STILL_ACTIVE;
    }

    template <typename T>
    T Read(uintptr_t address) const {
        T value{};
        if (!handle || address < 0x10000) return value;
        SIZE_T got = 0;
        ReadProcessMemory(handle, reinterpret_cast<LPCVOID>(address), &value, sizeof(T), &got);
        return (got == sizeof(T)) ? value : T{};
    }

    template <typename T>
    bool Read(uintptr_t address, T& out) const {
        if (!handle || address < 0x10000) return false;
        SIZE_T got = 0;
        return ReadProcessMemory(handle, reinterpret_cast<LPCVOID>(address), &out, sizeof(T), &got)
               && got == sizeof(T);
    }

    bool ReadBuffer(uintptr_t address, void* out, size_t size) const {
        if (!handle || address < 0x10000) return false;
        SIZE_T got = 0;
        return ReadProcessMemory(handle, reinterpret_cast<LPCVOID>(address), out, size, &got)
               && got == size;
    }

    std::string ReadString(uintptr_t address, size_t maxLen = 64) const {
        if (!handle || address < 0x10000) return {};
        char buf[128] = {};
        size_t n = (maxLen < sizeof(buf) - 1) ? maxLen : sizeof(buf) - 1;
        SIZE_T got = 0;
        if (!ReadProcessMemory(handle, reinterpret_cast<LPCVOID>(address), buf, n, &got) || got == 0)
            return {};
        buf[got] = '\0';
        return std::string(buf);
    }

    static bool ParsePattern(const std::string& sig,
                             std::vector<uint8_t>& bytes,
                             std::vector<uint8_t>& mask) {
        bytes.clear(); mask.clear();
        size_t i = 0;
        while (i < sig.size()) {
            while (i < sig.size() && isspace((unsigned char)sig[i])) ++i;
            if (i >= sig.size()) break;
            std::string tok;
            while (i < sig.size() && !isspace((unsigned char)sig[i])) tok += sig[i++];
            if (!tok.empty() && tok[0] == '?') {
                bytes.push_back(0); mask.push_back(0);
            } else {
                bytes.push_back((uint8_t)strtoul(tok.c_str(), nullptr, 16));
                mask.push_back(1);
            }
        }
        return !bytes.empty();
    }

    uintptr_t Scan(const std::string& sig) const {
        std::vector<uint8_t> bytes, mask;
        if (!ParsePattern(sig, bytes, mask)) return 0;
        const size_t patLen = bytes.size();
        if (!moduleBase || moduleSize < patLen) return 0;

        const size_t CHUNK = 0x1000000;
        std::vector<uint8_t> buf(CHUNK + patLen);

        for (size_t off = 0; off + patLen <= moduleSize; off += CHUNK) {
            size_t want = (std::min)(CHUNK + patLen, moduleSize - off);
            SIZE_T got = 0;
            if (!ReadProcessMemory(handle, reinterpret_cast<LPCVOID>(moduleBase + off),
                                   buf.data(), want, &got) || got < patLen)
                continue;
            for (size_t i = 0; i + patLen <= got; ++i) {
                bool ok = true;
                for (size_t j = 0; j < patLen; ++j) {
                    if (mask[j] && buf[i + j] != bytes[j]) { ok = false; break; }
                }
                if (ok) return moduleBase + off + i;
            }
        }
        return 0;
    }

private:
    struct ProcHit { DWORD pid; std::wstring exe; };
    struct WinCtx  { DWORD pid; bool found; };

    static bool IsServer(const std::wstring& n) {
        return _wcsnicmp(n.c_str(), L"ArmaReforgerServer", 18) == 0;
    }

    static BOOL CALLBACK WindowProcCb(HWND h, LPARAM lp) {
        auto* c = reinterpret_cast<WinCtx*>(lp);
        DWORD wpid = 0;
        GetWindowThreadProcessId(h, &wpid);
        if (wpid == c->pid && IsWindowVisible(h) && GetWindow(h, GW_OWNER) == nullptr) {
            c->found = true;
            return FALSE;
        }
        return TRUE;
    }

    static bool HasMainWindow(DWORD pid) {
        WinCtx c{ pid, false };
        EnumWindows(WindowProcCb, reinterpret_cast<LPARAM>(&c));
        return c.found;
    }

    // Prefix match: catches ArmaReforgerSteam / _BE / SteamDiag / MS / anything renamed.
    static bool CollectGameProcesses(std::vector<ProcHit>& out) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (snap == INVALID_HANDLE_VALUE) return false;
        PROCESSENTRY32W pe{};
        pe.dwSize = sizeof(pe);
        if (Process32FirstW(snap, &pe)) {
            do {
                if (_wcsnicmp(pe.szExeFile, L"ArmaReforger", 12) == 0)
                    out.push_back({ pe.th32ProcessID, pe.szExeFile });
            } while (Process32NextW(snap, &pe));
        }
        CloseHandle(snap);
        return true;
    }

    static bool FindModule(HANDLE, DWORD pid, const std::wstring& name,
                           uintptr_t& base, size_t& size) {
        HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE | TH32CS_SNAPMODULE32, pid);
        if (snap == INVALID_HANDLE_VALUE) return false;
        MODULEENTRY32W me{};
        me.dwSize = sizeof(me);
        bool found = false;
        if (Module32FirstW(snap, &me)) {
            do {
                if (_wcsicmp(me.szModule, name.c_str()) == 0) {
                    base = (uintptr_t)me.modBaseAddr;
                    size = (size_t)me.modBaseSize;
                    found = true;
                    break;
                }
            } while (Module32NextW(snap, &me));
        }
        CloseHandle(snap);
        return found;
    }

    // Fallback for when the toolhelp module snapshot refuses to cooperate.
    static bool FindMainModule(HANDLE ph, uintptr_t& base, size_t& size) {
        HMODULE mods[1]{};
        DWORD needed = 0;
        if (!EnumProcessModulesEx(ph, mods, sizeof(mods), &needed, LIST_MODULES_ALL)) return false;
        MODULEINFO mi{};
        if (!GetModuleInformation(ph, mods[0], &mi, sizeof(mi))) return false;
        base = (uintptr_t)mi.lpBaseOfDll;
        size = (size_t)mi.SizeOfImage;
        return base != 0;
    }
};

// ===========================================================================
//  offsets
// ===========================================================================
struct Offsets {
    uintptr_t Game                  = 0x1D4FCE8;
    uintptr_t GameWorld             = 0x130;
    uintptr_t LocalPlayerController = 0x378;
    uintptr_t WeakPtr               = 0x8;
    uintptr_t LocalPlayerDelta      = 0x10;
    uintptr_t LocalPlayerCamera     = 0xD0;
    uintptr_t AVCameraManager       = 0x308;

    uintptr_t CameraPosition        = 0x68;
    uintptr_t InvertedViewRight     = 0x80;
    uintptr_t InvertedViewUp        = 0x8C;
    uintptr_t VectorViewForward     = 0x98;
    uintptr_t FirstPersonFOV        = 0x128;

    uintptr_t EntityList            = 0xF8;
    uintptr_t EntityCount           = 0x104;
    uintptr_t EntityPosition        = 0x8C;

    uintptr_t HealthChain1          = 0x158;
    uintptr_t HealthChain2          = 0xD8;
    uintptr_t Health                = 0x44;
    uintptr_t MaxHealth             = 0x40;

    uintptr_t FactionComponent      = 0x0;
    uintptr_t FactionPointer        = 0x0;
    uintptr_t FactionKey            = 0x0;

    uintptr_t BoneChain1            = 0x50;
    uintptr_t BoneChain2            = 0x30;
    uintptr_t BonesList             = 0xE0;
    uintptr_t BoneCountOffset       = 0xE8;
    uintptr_t BoneStride            = 0x30;
    uintptr_t BonePosOffset         = 0x24;
    uintptr_t EntityTransform       = 0x68;
    int       HeadBone              = 36;
    int       TransposeBoneMat      = 0;

    int         UseAob              = 0;
    std::string GameAob             = "";
    intptr_t    GameAobOffset       = 0;
};

inline std::string TrimStr(const std::string& s) {
    size_t a = s.find_first_not_of(" \t\r\n");
    if (a == std::string::npos) return "";
    size_t b = s.find_last_not_of(" \t\r\n");
    return s.substr(a, b - a + 1);
}

inline bool LoadOffsets(const char* path, Offsets& o) {
    FILE* f = fopen(path, "r");
    if (!f) return false;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char* semi = strchr(line, ';');
        if (semi) *semi = '\0';
        if (line[0] == '[') continue;
        char* eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        std::string key = TrimStr(line), val = TrimStr(eq + 1);
        if (key.empty() || val.empty()) continue;
        auto hex = [&]() -> uintptr_t { return (uintptr_t)strtoull(val.c_str(), nullptr, 0); };

        if      (key == "Game")                  o.Game = hex();
        else if (key == "GameWorld")             o.GameWorld = hex();
        else if (key == "LocalPlayerController") o.LocalPlayerController = hex();
        else if (key == "WeakPtr")               o.WeakPtr = hex();
        else if (key == "LocalPlayerDelta")      o.LocalPlayerDelta = hex();
        else if (key == "LocalPlayerCamera")     o.LocalPlayerCamera = hex();
        else if (key == "AVCameraManager")       o.AVCameraManager = hex();
        else if (key == "CameraPosition")        o.CameraPosition = hex();
        else if (key == "InvertedViewRight")     o.InvertedViewRight = hex();
        else if (key == "InvertedViewUp")        o.InvertedViewUp = hex();
        else if (key == "VectorViewForward")     o.VectorViewForward = hex();
        else if (key == "FirstPersonFOV")        o.FirstPersonFOV = hex();
        else if (key == "EntityList")            o.EntityList = hex();
        else if (key == "EntityCount")           o.EntityCount = hex();
        else if (key == "EntityPosition")        o.EntityPosition = hex();
        else if (key == "HealthChain1")          o.HealthChain1 = hex();
        else if (key == "HealthChain2")          o.HealthChain2 = hex();
        else if (key == "Health")                o.Health = hex();
        else if (key == "MaxHealth")             o.MaxHealth = hex();
        else if (key == "FactionComponent")      o.FactionComponent = hex();
        else if (key == "FactionPointer")        o.FactionPointer = hex();
        else if (key == "FactionKey")            o.FactionKey = hex();
        else if (key == "BoneChain1")            o.BoneChain1 = hex();
        else if (key == "BoneChain2")            o.BoneChain2 = hex();
        else if (key == "BonesList")             o.BonesList = hex();
        else if (key == "BoneCountOffset")       o.BoneCountOffset = hex();
        else if (key == "BoneStride")            o.BoneStride = hex();
        else if (key == "BonePosOffset")         o.BonePosOffset = hex();
        else if (key == "EntityTransform")       o.EntityTransform = hex();
        else if (key == "HeadBone")              o.HeadBone = atoi(val.c_str());
        else if (key == "TransposeBoneMat")      o.TransposeBoneMat = atoi(val.c_str());
        else if (key == "UseAob")                o.UseAob = atoi(val.c_str());
        else if (key == "GameAob")               o.GameAob = val;
        else if (key == "GameAobOffset")         o.GameAobOffset = (intptr_t)strtoll(val.c_str(), nullptr, 0);
    }
    fclose(f);
    return true;
}

inline void SaveOffsets(const char* path, const Offsets& o) {
    FILE* f = fopen(path, "w");
    if (!f) return;
    fprintf(f,
        "; Arma Reforger external offsets - edit after every game patch.\n"
        "; Find them with Cheat Engine: pointer scan from your own health float.\n"
        "; Values accept 0x hex or decimal.\n\n"
        "[base]\n"
        "Game = 0x%llX\nUseAob = %d\nGameAob = %s\nGameAobOffset = 0x%llX\n\n"
        "[chain]\n"
        "GameWorld = 0x%llX\nLocalPlayerController = 0x%llX\nWeakPtr = 0x%llX\n"
        "LocalPlayerDelta = 0x%llX\nLocalPlayerCamera = 0x%llX\nAVCameraManager = 0x%llX\n\n"
        "[camera]\n"
        "CameraPosition = 0x%llX\nInvertedViewRight = 0x%llX\nInvertedViewUp = 0x%llX\n"
        "VectorViewForward = 0x%llX\nFirstPersonFOV = 0x%llX\n\n"
        "[world]\n"
        "EntityList = 0x%llX\nEntityCount = 0x%llX\nEntityPosition = 0x%llX\n\n"
        "[character]\n"
        "HealthChain1 = 0x%llX\nHealthChain2 = 0x%llX\n"
        "Health = 0x%llX\nMaxHealth = 0x%llX\n\n"
        "[team]\n"
        "FactionComponent = 0x%llX\nFactionPointer = 0x%llX\nFactionKey = 0x%llX\n\n"
        "[skeleton]\n"
        "BoneChain1 = 0x%llX\nBoneChain2 = 0x%llX\nBonesList = 0x%llX\n"
        "BoneCountOffset = 0x%llX\nBoneStride = 0x%llX\nBonePosOffset = 0x%llX\n"
        "EntityTransform = 0x%llX\nHeadBone = %d\nTransposeBoneMat = %d\n",
        (unsigned long long)o.Game, o.UseAob,
        o.GameAob.empty() ? "" : o.GameAob.c_str(),
        (unsigned long long)o.GameAobOffset,
        (unsigned long long)o.GameWorld,
        (unsigned long long)o.LocalPlayerController,
        (unsigned long long)o.WeakPtr,
        (unsigned long long)o.LocalPlayerDelta,
        (unsigned long long)o.LocalPlayerCamera,
        (unsigned long long)o.AVCameraManager,
        (unsigned long long)o.CameraPosition,
        (unsigned long long)o.InvertedViewRight,
        (unsigned long long)o.InvertedViewUp,
        (unsigned long long)o.VectorViewForward,
        (unsigned long long)o.FirstPersonFOV,
        (unsigned long long)o.EntityList,
        (unsigned long long)o.EntityCount,
        (unsigned long long)o.EntityPosition,
        (unsigned long long)o.HealthChain1,
        (unsigned long long)o.HealthChain2,
        (unsigned long long)o.Health,
        (unsigned long long)o.MaxHealth,
        (unsigned long long)o.FactionComponent,
        (unsigned long long)o.FactionPointer,
        (unsigned long long)o.FactionKey,
        (unsigned long long)o.BoneChain1,
        (unsigned long long)o.BoneChain2,
        (unsigned long long)o.BonesList,
        (unsigned long long)o.BoneCountOffset,
        (unsigned long long)o.BoneStride,
        (unsigned long long)o.BonePosOffset,
        (unsigned long long)o.EntityTransform,
        o.HeadBone,
        o.TransposeBoneMat);
    fclose(f);
}

// ===========================================================================
//  config
// ===========================================================================
struct Config {
    bool  espEnabled   = true;
    bool  boxEsp       = true;
    bool  snaplines    = false;
    bool  showNames    = true;
    bool  healthBar    = true;
    bool  showDistance = true;
    bool  showLocal    = false;
    bool  fovCircle    = true;

    bool  aimEnabled   = true;
    bool  humanize     = true;
    bool  predict      = true;

    bool  skeleton     = true;
    bool  teamCheck    = false;
    bool  colorTeammates = true;
    bool  hideTeammates  = false;
    bool  aimHeadBone    = true;

    float maxDistance  = 800.f;
    float aimFov       = 120.f;
    float aimSpeed     = 10.f;
    float aimHeight    = 1.72f;
    float jitter       = 1.5f;
    float aimScale     = 1.0f;
    float bulletSpeed  = 850.f;

    float skeletonMaxDistance = 250.f;
    int   skeletonMaxCount    = 16;

    int   aimKey       = VK_RBUTTON;
    int   maxEntities  = 8192;
    int   fontSize     = 13;

    COLORREF colBox      = RGB(255, 255, 255);
    COLORREF colSnapline = RGB(255, 255, 255);
    COLORREF colName     = RGB(255, 255, 255);
    COLORREF colDist     = RGB(205, 205, 205);
    COLORREF colHealth   = RGB(0, 255, 130);
    COLORREF colFov      = RGB(170, 170, 170);
    COLORREF colText     = RGB(255, 255, 255);
    COLORREF colWarn     = RGB(255, 90, 90);
    COLORREF colTeam     = RGB(0, 220, 255);
    COLORREF colSkeleton = RGB(255, 205, 0);
};

inline bool ParseBool(const std::string& v) {
    return v == "1" || v == "true" || v == "on" || v == "yes";
}

inline COLORREF ParseColor(const std::string& v, COLORREF def) {
    int r, g, b;
    if (sscanf(v.c_str(), "%d,%d,%d", &r, &g, &b) == 3) return RGB(r, g, b);
    return def;
}

inline void LoadConfig(const char* path, Config& c) {
    FILE* f = fopen(path, "r");
    if (!f) return;
    char line[512];
    while (fgets(line, sizeof(line), f)) {
        char* semi = strchr(line, ';');
        if (semi) *semi = '\0';
        if (line[0] == '[') continue;
        char* eq = strchr(line, '=');
        if (!eq) continue;
        *eq = '\0';
        std::string k = TrimStr(line), v = TrimStr(eq + 1);
        if (k.empty() || v.empty()) continue;

        if      (k == "esp_enabled")    c.espEnabled   = ParseBool(v);
        else if (k == "box")            c.boxEsp       = ParseBool(v);
        else if (k == "snaplines")      c.snaplines    = ParseBool(v);
        else if (k == "names")          c.showNames    = ParseBool(v);
        else if (k == "health_bar")     c.healthBar    = ParseBool(v);
        else if (k == "distance")       c.showDistance = ParseBool(v);
        else if (k == "show_local")     c.showLocal    = ParseBool(v);
        else if (k == "fov_circle")     c.fovCircle    = ParseBool(v);
        else if (k == "aim_enabled")    c.aimEnabled   = ParseBool(v);
        else if (k == "humanize")       c.humanize     = ParseBool(v);
        else if (k == "predict")        c.predict      = ParseBool(v);
        else if (k == "skeleton")       c.skeleton     = ParseBool(v);
        else if (k == "team_check")     c.teamCheck    = ParseBool(v);
        else if (k == "color_teammates") c.colorTeammates = ParseBool(v);
        else if (k == "hide_teammates") c.hideTeammates = ParseBool(v);
        else if (k == "aim_head_bone")  c.aimHeadBone  = ParseBool(v);
        else if (k == "max_distance")   c.maxDistance  = (float)atof(v.c_str());
        else if (k == "aim_fov")        c.aimFov       = (float)atof(v.c_str());
        else if (k == "aim_speed")      c.aimSpeed     = (float)atof(v.c_str());
        else if (k == "aim_height")     c.aimHeight    = (float)atof(v.c_str());
        else if (k == "jitter")         c.jitter       = (float)atof(v.c_str());
        else if (k == "aim_scale")      c.aimScale     = (float)atof(v.c_str());
        else if (k == "bullet_speed")   c.bulletSpeed  = (float)atof(v.c_str());
        else if (k == "skeleton_max_distance") c.skeletonMaxDistance = (float)atof(v.c_str());
        else if (k == "skeleton_max_count")    c.skeletonMaxCount = atoi(v.c_str());
        else if (k == "max_entities")   c.maxEntities  = atoi(v.c_str());
        else if (k == "font_size")      c.fontSize     = atoi(v.c_str());
        else if (k == "col_box")        c.colBox       = ParseColor(v, c.colBox);
        else if (k == "col_snapline")   c.colSnapline  = ParseColor(v, c.colSnapline);
        else if (k == "col_name")       c.colName      = ParseColor(v, c.colName);
        else if (k == "col_distance")   c.colDist      = ParseColor(v, c.colDist);
        else if (k == "col_health")     c.colHealth    = ParseColor(v, c.colHealth);
        else if (k == "col_team")       c.colTeam      = ParseColor(v, c.colTeam);
        else if (k == "col_skeleton")   c.colSkeleton  = ParseColor(v, c.colSkeleton);
    }
    fclose(f);
}

inline void SaveConfig(const char* path, const Config& c) {
    FILE* f = fopen(path, "w");
    if (!f) return;
    fprintf(f,
        "; Reforger External settings. Delete this file to regenerate defaults.\n\n"
        "[esp]\n"
        "esp_enabled = %d\nbox = %d\nsnaplines = %d\nnames = %d\nhealth_bar = %d\n"
        "distance = %d\nshow_local = %d\nfov_circle = %d\nmax_distance = %.1f\n\n"
        "[aim]\n"
        "aim_enabled = %d\nhumanize = %d\npredict = %d\n"
        "aim_fov = %.1f\naim_speed = %.2f\naim_height = %.2f\njitter = %.2f\n"
        "aim_scale = %.3f\nbullet_speed = %.0f\n\n"
        "[team]\n"
        "team_check = %d\ncolor_teammates = %d\nhide_teammates = %d\n"
        "col_team = %d,%d,%d\n\n"
        "[skeleton]\n"
        "skeleton = %d\naim_head_bone = %d\n"
        "skeleton_max_distance = %.0f\nskeleton_max_count = %d\n"
        "col_skeleton = %d,%d,%d\n\n"
        "[perf]\nmax_entities = %d\nfont_size = %d\n\n"
        "[colors]\n"
        "col_box = %d,%d,%d\ncol_snapline = %d,%d,%d\ncol_name = %d,%d,%d\n"
        "col_distance = %d,%d,%d\ncol_health = %d,%d,%d\n",
        c.espEnabled, c.boxEsp, c.snaplines, c.showNames, c.healthBar,
        c.showDistance, c.showLocal, c.fovCircle, c.maxDistance,
        c.aimEnabled, c.humanize, c.predict,
        c.aimFov, c.aimSpeed, c.aimHeight, c.jitter, c.aimScale, c.bulletSpeed,
        c.teamCheck, c.colorTeammates, c.hideTeammates,
        GetRValue(c.colTeam), GetGValue(c.colTeam), GetBValue(c.colTeam),
        c.skeleton, c.aimHeadBone, c.skeletonMaxDistance, c.skeletonMaxCount,
        GetRValue(c.colSkeleton), GetGValue(c.colSkeleton), GetBValue(c.colSkeleton),
        c.maxEntities, c.fontSize,
        GetRValue(c.colBox), GetGValue(c.colBox), GetBValue(c.colBox),
        GetRValue(c.colSnapline), GetGValue(c.colSnapline), GetBValue(c.colSnapline),
        GetRValue(c.colName), GetGValue(c.colName), GetBValue(c.colName),
        GetRValue(c.colDist), GetGValue(c.colDist), GetBValue(c.colDist),
        GetRValue(c.colHealth), GetGValue(c.colHealth), GetBValue(c.colHealth));
    fclose(f);
}

// ===========================================================================
//  overlay - per-pixel alpha layered window.
//  GDI writes 0 into the alpha byte, so alpha is synthesised from "non-black".
//  That is why outlines use RGB(1,1,1) and never pure black.
// ===========================================================================
class Overlay {
public:
    static constexpr COLORREF OUTLINE = RGB(1, 1, 1);

    bool Create() {
        WNDCLASSEXW wc = {};
        wc.cbSize        = sizeof(wc);
        wc.lpfnWndProc   = DefWindowProcW;
        wc.hInstance     = GetModuleHandleW(nullptr);
        wc.lpszClassName = L"ReforgerExternalOverlay";
        RegisterClassExW(&wc);

        hwnd = CreateWindowExW(
            WS_EX_TOPMOST | WS_EX_LAYERED | WS_EX_TRANSPARENT |
            WS_EX_TOOLWINDOW | WS_EX_NOACTIVATE,
            L"ReforgerExternalOverlay", L"ReforgerExternal",
            WS_POPUP, 0, 0, 100, 100,
            nullptr, nullptr, wc.hInstance, nullptr);

        if (!hwnd) return false;
        ShowWindow(hwnd, SW_SHOWNOACTIVATE);
        SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE);
        return true;
    }

    void Destroy() {
        for (auto& kv : pens)  DeleteObject(kv.second);
        for (auto& kv : fonts) DeleteObject(kv.second);
        pens.clear(); fonts.clear();
        if (memDC)    { if (dib) SelectObject(memDC, oldBmp); DeleteDC(memDC); memDC = nullptr; }
        if (dib)      { DeleteObject(dib); dib = nullptr; }
        if (screenDC) { ReleaseDC(nullptr, screenDC); screenDC = nullptr; }
        if (hwnd)     { DestroyWindow(hwnd); hwnd = nullptr; }
        bits = nullptr;
    }

    int  Width()  const { return width; }
    int  Height() const { return height; }

    void SetBounds(int x, int y, int w, int h) {
        if (w < 1) w = 1;
        if (h < 1) h = 1;
        if (x == posX && y == posY && w == width && h == height) return;
        posX = x; posY = y; width = w; height = h;
        Recreate();
    }

    void Begin() {
        if (!bits) return;
        memset(bits, 0, (size_t)width * (size_t)height * 4u);
    }

    void Present() {
        if (!hwnd || !bits) return;
        const size_t n = (size_t)width * (size_t)height;
        for (size_t i = 0; i < n; ++i) {
            uint32_t c = bits[i] & 0x00FFFFFFu;
            bits[i] = c ? (c | 0xFF000000u) : 0u;
        }
        HDC screen = GetDC(nullptr);
        POINT dst{ posX, posY }, src{ 0, 0 };
        SIZE  size{ width, height };
        BLENDFUNCTION blend{ AC_SRC_OVER, 0, 255, AC_SRC_ALPHA };
        UpdateLayeredWindow(hwnd, screen, &dst, &size, memDC, &src, 0, &blend, ULW_ALPHA);
        ReleaseDC(nullptr, screen);
    }

    void Line(float x1, float y1, float x2, float y2, COLORREF col, int t = 1) {
        if (!memDC) return;
        HPEN pen = GetPen(col, t), old = (HPEN)SelectObject(memDC, pen);
        MoveToEx(memDC, (int)lroundf(x1), (int)lroundf(y1), nullptr);
        LineTo(memDC, (int)lroundf(x2), (int)lroundf(y2));
        SelectObject(memDC, old);
    }

    void Rect(float x, float y, float w, float h, COLORREF col, int t = 1) {
        if (!memDC) return;
        HPEN pen = GetPen(col, t), op = (HPEN)SelectObject(memDC, pen);
        HBRUSH ob = (HBRUSH)SelectObject(memDC, GetStockObject(NULL_BRUSH));
        Rectangle(memDC, (int)x, (int)y, (int)(x + w), (int)(y + h));
        SelectObject(memDC, ob);
        SelectObject(memDC, op);
    }

    void FillRect(float x, float y, float w, float h, COLORREF col) {
        if (!memDC) return;
        RECT r{ (LONG)x, (LONG)y, (LONG)(x + w), (LONG)(y + h) };
        HBRUSH b = CreateSolidBrush(col);
        ::FillRect(memDC, &r, b);
        DeleteObject(b);
    }

    void Circle(float cx, float cy, float radius, COLORREF col, int t = 1) {
        if (!memDC) return;
        HPEN pen = GetPen(col, t), op = (HPEN)SelectObject(memDC, pen);
        HBRUSH ob = (HBRUSH)SelectObject(memDC, GetStockObject(NULL_BRUSH));
        Ellipse(memDC, (int)(cx - radius), (int)(cy - radius),
                       (int)(cx + radius), (int)(cy + radius));
        SelectObject(memDC, ob);
        SelectObject(memDC, op);
    }

    void Text(float x, float y, const std::wstring& s, COLORREF col,
              int size = 13, bool centered = false, bool shadow = true) {
        if (!memDC || s.empty()) return;
        HFONT font = GetFont(size);
        HFONT of = (HFONT)SelectObject(memDC, font);
        SetBkMode(memDC, TRANSPARENT);

        SIZE sz{};
        GetTextExtentPoint32W(memDC, s.c_str(), (int)s.size(), &sz);
        int px = (int)lroundf(centered ? (x - sz.cx * 0.5f) : x);
        int py = (int)lroundf(y);

        if (shadow) {
            SetTextColor(memDC, OUTLINE);
            TextOutW(memDC, px + 1, py,     s.c_str(), (int)s.size());
            TextOutW(memDC, px - 1, py,     s.c_str(), (int)s.size());
            TextOutW(memDC, px,     py + 1, s.c_str(), (int)s.size());
            TextOutW(memDC, px,     py - 1, s.c_str(), (int)s.size());
        }
        SetTextColor(memDC, col);
        TextOutW(memDC, px, py, s.c_str(), (int)s.size());
        SelectObject(memDC, of);
    }

private:
    HWND      hwnd = nullptr;
    HDC       screenDC = nullptr, memDC = nullptr;
    HBITMAP   dib = nullptr, oldBmp = nullptr;
    uint32_t* bits = nullptr;
    int       posX = 0, posY = 0, width = 0, height = 0;

    std::unordered_map<DWORD, HPEN> pens;
    std::unordered_map<int, HFONT>  fonts;

    HPEN GetPen(COLORREF col, int t) {
        DWORD key = ((DWORD)col) ^ ((DWORD)(t & 0xFF) << 24);
        auto it = pens.find(key);
        if (it != pens.end()) return it->second;
        HPEN p = CreatePen(PS_SOLID, t, col);
        pens[key] = p;
        return p;
    }

    HFONT GetFont(int size) {
        auto it = fonts.find(size);
        if (it != fonts.end()) return it->second;
        HFONT f = CreateFontW(-size, 0, 0, 0, FW_SEMIBOLD, FALSE, FALSE, FALSE,
                              DEFAULT_CHARSET, OUT_TT_PRECIS, CLIP_DEFAULT_PRECIS,
                              ANTIALIASED_QUALITY, DEFAULT_PITCH | FF_DONTCARE,
                              L"Consolas");
        fonts[size] = f;
        return f;
    }

    void Recreate() {
        if (memDC) { if (dib) SelectObject(memDC, oldBmp); DeleteDC(memDC); memDC = nullptr; }
        if (dib)   { DeleteObject(dib); dib = nullptr; }
        if (screenDC) { ReleaseDC(nullptr, screenDC); screenDC = nullptr; }
        bits = nullptr;

        screenDC = GetDC(nullptr);
        memDC = CreateCompatibleDC(screenDC);

        BITMAPINFO bmi = {};
        bmi.bmiHeader.biSize        = sizeof(BITMAPINFOHEADER);
        bmi.bmiHeader.biWidth       = width;
        bmi.bmiHeader.biHeight      = -height;
        bmi.bmiHeader.biPlanes      = 1;
        bmi.bmiHeader.biBitCount    = 32;
        bmi.bmiHeader.biCompression = BI_RGB;

        void* raw = nullptr;
        dib = CreateDIBSection(screenDC, &bmi, DIB_RGB_COLORS, &raw, nullptr, 0);
        bits = reinterpret_cast<uint32_t*>(raw);
        if (dib) oldBmp = (HBITMAP)SelectObject(memDC, dib);
        SetBkMode(memDC, TRANSPARENT);
    }
};

// ===========================================================================
//  game
// ===========================================================================
static constexpr int kMaxBones = 256;

struct BonePair { int a, b; };
static const BonePair kBonePairs[] = {
    {4, 16}, {16, 31}, {31, 32}, {32, 33}, {33, 34}, {34, 36},
    {34, 39}, {39, 45}, {45, 48}, {48, 51},
    {34, 43}, {43, 198}, {198, 201},
    {4, 10},  {10, 19}, {19, 22}, {22, 23},
    {4, 13},  {13, 26}, {26, 29}, {29, 30},
};
static constexpr int kBonePairCount = (int)(sizeof(kBonePairs) / sizeof(kBonePairs[0]));

struct Mat34 {
    float m[12] = {};

    bool Valid() const {
        for (int i = 0; i < 12; ++i) if (!std::isfinite(m[i])) return false;
        float len = sqrtf(m[0] * m[0] + m[1] * m[1] + m[2] * m[2]);
        return len > 1e-4f && len < 1e4f;
    }

    Vec3 Transform(const Vec3& p, bool transpose) const {
        if (transpose)
            return Vec3(m[0] * p.x + m[1] * p.y + m[2] * p.z + m[9],
                        m[3] * p.x + m[4] * p.y + m[5] * p.z + m[10],
                        m[6] * p.x + m[7] * p.y + m[8] * p.z + m[11]);
        return Vec3(m[0] * p.x + m[3] * p.y + m[6] * p.z + m[9],
                    m[1] * p.x + m[4] * p.y + m[7] * p.z + m[10],
                    m[2] * p.x + m[5] * p.y + m[8] * p.z + m[11]);
    }
};

struct PlayerEntity {
    uintptr_t   address   = 0;
    Vec3        feet;
    Vec3        velocity;
    float       health    = 0.f;
    float       maxHealth = 0.f;
    float       distance  = 0.f;
    bool        onScreen  = false;
    bool        isLocal   = false;

    bool        isTeammate = false;
    std::string factionKey;
    std::string name;

    Vec2        headScreen, feetScreen;
    Vec3        aimWorld;
    Vec2        aimScreen;
    bool        aimOnScreen = false;
    float       crosshairDist = 1e9f;

    std::array<Vec2, kMaxBones>    boneScreen{};
    std::array<uint8_t, kMaxBones> boneOk{};
    bool        headBoneOk   = false;
    Vec3        headBoneWorld;
};

struct Camera {
    Vec3  position, right, up, forward;
    float fov   = 1.15f;
    bool  valid = false;
};

struct GameState {
    uintptr_t game = 0, world = 0, localEntity = 0, playerCamera = 0;
    uintptr_t localFaction = 0;
    std::string localFactionKey;

    Camera    camera;
    std::vector<PlayerEntity> players;
    std::vector<uintptr_t>    rawEntities;
    std::vector<std::wstring> scanResults;

    int       entityCount = 0;
    int       candidates  = 0;
    bool      ok          = false;
    std::wstring status;
};

class Game {
public:
    Memory* mem = nullptr;
    Offsets off;

    float maxDistance         = 800.f;
    float aimHeight           = 1.72f;
    int   maxEntities         = 8192;
    bool  showLocal           = false;
    bool  teamCheck           = false;
    float skeletonMaxDistance = 250.f;
    int   skeletonMaxCount    = 16;

    std::unordered_map<uintptr_t, std::pair<Vec3, double>> prevPositions;

    bool WorldToScreen(const Camera& cam, const Vec3& world, Vec2& out, int w, int h) const {
        if (!cam.valid) return false;
        Vec3 d = world - cam.position;
        float x = d.Dot(cam.right);
        float y = d.Dot(cam.up);
        float z = d.Dot(cam.forward);
        if (z <= 0.05f) return false;

        float tanY = tanf(cam.fov * 0.5f);
        if (tanY < 1e-6f) return false;
        float tanX = tanY * ((float)w / (float)h);

        out.x = (w * 0.5f) * (1.f + (x / z) / tanX);
        out.y = (h * 0.5f) * (1.f - (y / z) / tanY);
        return true;
    }

    void Update(GameState& st, int w, int h, double now) {
        st.ok = false;
        st.players.clear();
        st.rawEntities.clear();
        st.status.clear();

        uintptr_t gamePtr = 0;
        if (off.UseAob && !off.GameAob.empty()) {
            uintptr_t hit = mem->Scan(off.GameAob);
            if (hit) gamePtr = mem->Read<uintptr_t>(hit + off.GameAobOffset);
        } else {
            gamePtr = mem->Read<uintptr_t>(mem->moduleBase + off.Game);
        }
        if (!gamePtr) { st.status = L"Game pointer null - fix offsets.ini"; return; }
        st.game = gamePtr;

        if (!ReadLocalAndCamera(st)) return;
        ReadEntities(st, w, h, now);
        st.ok = st.camera.valid;
    }

    uintptr_t ResolveFaction(uintptr_t entity) const {
        if (!off.FactionPointer) return 0;
        uintptr_t base = entity;
        if (off.FactionComponent) {
            base = mem->Read<uintptr_t>(entity + off.FactionComponent);
            if (!base) return 0;
        }
        return mem->Read<uintptr_t>(base + off.FactionPointer);
    }

    bool PlausibleObject(uintptr_t p) const {
        if (p < 0x10000 || p > 0x7FFFFFFFFFFFull) return false;
        if (p & 0x7) return false;
        uintptr_t vt = mem->Read<uintptr_t>(p);
        return vt >= mem->moduleBase && vt < mem->moduleBase + mem->moduleSize;
    }

    void RunFactionScan(GameState& st) {
        st.scanResults.clear();
        if (!st.localEntity) { st.scanResults.push_back(L"scan: no local entity"); return; }
        std::vector<uintptr_t> ents = st.rawEntities;
        if (ents.size() > 64) ents.resize(64);
        if (ents.empty()) { st.scanResults.push_back(L"scan: no entities"); return; }

        struct Hit { uintptr_t off; int shared; int total; };
        std::vector<Hit> hits;

        for (uintptr_t o = 0x8; o < 0x800; o += 8) {
            uintptr_t localVal = mem->Read<uintptr_t>(st.localEntity + o);
            if (!PlausibleObject(localVal)) continue;

            int shared = 0, total = 0;
            for (uintptr_t e : ents) {
                uintptr_t v = mem->Read<uintptr_t>(e + o);
                if (!PlausibleObject(v)) continue;
                total++;
                if (v == localVal) shared++;
            }
            if (shared >= 1) hits.push_back({ o, shared, total });
        }

        std::sort(hits.begin(), hits.end(), [](const Hit& a, const Hit& b) {
            if (a.shared != b.shared) return a.shared > b.shared;
            return a.off < b.off;
        });

        wchar_t buf[128];
        st.scanResults.push_back(L"FACTION SCAN - offset  shared/total");
        for (size_t i = 0; i < hits.size() && i < 12; ++i) {
            swprintf_s(buf, L"  0x%llX   %d / %d",
                       (unsigned long long)hits[i].off, hits[i].shared, hits[i].total);
            st.scanResults.push_back(buf);
        }
        if (hits.empty()) st.scanResults.push_back(L"  nothing shared - wrong build?");
        st.scanResults.push_back(L"pick the row shared with ~half the players");
    }

private:
    bool ReadLocalAndCamera(GameState& st) {
        st.camera.valid = false;
        st.localFaction = 0;

        uintptr_t world = mem->Read<uintptr_t>(st.game + off.GameWorld);
        if (!world) { st.status = L"World null - check GameWorld"; return false; }
        st.world = world;

        uintptr_t ctrlWeak = mem->Read<uintptr_t>(world + off.LocalPlayerController);
        if (!ctrlWeak) { st.status = L"LocalPlayerController null"; return false; }
        uintptr_t ctrl = mem->Read<uintptr_t>(ctrlWeak + off.WeakPtr);
        if (!ctrl) { st.status = L"Controller weak deref null"; return false; }
        st.localEntity = ctrl - off.LocalPlayerDelta;

        if (off.FactionPointer) {
            st.localFaction = ResolveFaction(st.localEntity);
            if (st.localFaction && off.FactionKey) {
                uintptr_t keyPtr = mem->Read<uintptr_t>(st.localFaction + off.FactionKey);
                if (keyPtr) st.localFactionKey = mem->ReadString(keyPtr, 24);
            }
        }

        uintptr_t camMgrWeak = mem->Read<uintptr_t>(st.game + off.AVCameraManager);
        uintptr_t camMgr     = mem->Read<uintptr_t>(camMgrWeak + off.WeakPtr);
        float fov = camMgr ? mem->Read<float>(camMgr + off.FirstPersonFOV) : 0.f;
        if (fov > 6.f) fov *= 0.0174532925f;
        if (fov < 0.05f || fov > 3.0f) fov = 1.15f;

        uintptr_t pc = mem->Read<uintptr_t>(st.localEntity + off.LocalPlayerCamera);
        if (!pc) { st.status = L"PlayerCamera null"; return false; }
        st.playerCamera = pc;

        Camera cam;
        if (!mem->Read(pc + off.CameraPosition,    cam.position) ||
            !mem->Read(pc + off.InvertedViewRight, cam.right)    ||
            !mem->Read(pc + off.InvertedViewUp,    cam.up)       ||
            !mem->Read(pc + off.VectorViewForward, cam.forward)) {
            st.status = L"Camera read failed";
            return false;
        }
        cam.fov = fov;
        if (!cam.position.IsFinite() || !cam.forward.IsFinite() || cam.forward.IsZero()) {
            st.status = L"Camera values invalid";
            return false;
        }
        st.camera = cam;
        st.camera.valid = true;
        return true;
    }

    void ReadSkeleton(GameState& st, PlayerEntity& p, const uint8_t* block, int w, int h) {
        p.boneOk.fill(0);
        p.headBoneOk = false;
        if (!off.BonesList || off.BoneChain1 >= 0x200) return;

        uintptr_t holder = 0, mesh = 0;
        memcpy(&holder, block + off.BoneChain1, sizeof(uintptr_t));
        if (!holder) return;
        mesh = mem->Read<uintptr_t>(holder + off.BoneChain2);
        if (!mesh) return;

        uintptr_t bones = mem->Read<uintptr_t>(mesh + off.BonesList);
        int boneCount = mem->Read<int>(mesh + off.BoneCountOffset);
        if (boneCount < 8 || boneCount > kMaxBones) boneCount = kMaxBones;
        if (!bones) return;

        const size_t bytes = (size_t)boneCount * off.BoneStride;
        static std::vector<uint8_t> buf;
        if (buf.size() < bytes) buf.resize(bytes);
        if (!mem->ReadBuffer(bones, buf.data(), bytes)) return;

        bool worldSpace = true;
        {
            int probe = (off.HeadBone >= 0 && off.HeadBone < boneCount) ? off.HeadBone : 4;
            Vec3 b;
            memcpy(&b, buf.data() + (size_t)probe * off.BoneStride + off.BonePosOffset, sizeof(Vec3));
            if (b.IsFinite() && !b.IsZero()) {
                if (b.Distance(p.feet) < 3.f)                          worldSpace = true;
                else if (b.Length() < 50.f && p.feet.Length() > 100.f)  worldSpace = false;
                else                                                    worldSpace = (b.Length() > 100.f);
            }
        }

        Mat34 em;
        if (!worldSpace) {
            if (off.EntityTransform + sizeof(Mat34) > 0x200) return;
            memcpy(em.m, block + off.EntityTransform, sizeof(Mat34));
            if (!em.Valid()) return;
        }

        const bool transpose = off.TransposeBoneMat != 0;

        for (int i = 0; i < boneCount; ++i) {
            Vec3 b;
            memcpy(&b, buf.data() + (size_t)i * off.BoneStride + off.BonePosOffset, sizeof(Vec3));
            if (!b.IsFinite() || b.IsZero()) continue;
            Vec3 world = worldSpace ? b : em.Transform(b, transpose);

            Vec2 s;
            if (!WorldToScreen(st.camera, world, s, w, h)) continue;
            if (s.x < -2000.f || s.x > w + 2000.f) continue;

            p.boneScreen[i] = s;
            p.boneOk[i]     = 1;
            if (i == off.HeadBone) p.headBoneWorld = world;
        }

        if (off.HeadBone >= 0 && off.HeadBone < kMaxBones && p.boneOk[off.HeadBone])
            p.headBoneOk = true;
    }

    void ReadEntities(GameState& st, int w, int h, double now) {
        if (off.EntityPosition >= 0x200 || off.HealthChain1 >= 0x200) {
            st.status = L"offset >= 0x200 - widen the block read";
            return;
        }

        uintptr_t list = mem->Read<uintptr_t>(st.world + off.EntityList);
        int count = mem->Read<int>(st.world + off.EntityCount);
        st.entityCount = count;
        if (!list || count <= 0) { st.status = L"Entity list empty"; return; }
        if (count > maxEntities) count = maxEntities;

        std::vector<uintptr_t> ptrs((size_t)count);
        if (!mem->ReadBuffer(list, ptrs.data(), (size_t)count * sizeof(uintptr_t))) {
            st.status = L"Entity list read failed";
            return;
        }

        uint8_t block[0x200];
        const float cx = w * 0.5f, cy = h * 0.5f;
        const bool factionFilter = teamCheck && off.FactionPointer && st.localFaction != 0;

        auto consider = [&](uintptr_t ent, bool local) {
            if (!mem->ReadBuffer(ent, block, sizeof(block))) return;

            Vec3 pos;
            memcpy(&pos, block + off.EntityPosition, sizeof(Vec3));
            if (!pos.IsFinite() || pos.IsZero()) return;

            float dist = pos.Distance(st.camera.position);
            if (dist > maxDistance || dist < 0.05f) return;

            uintptr_t faction = 0;
            if (off.FactionPointer) {
                faction = local ? st.localFaction : ResolveFaction(ent);
                if (factionFilter && !faction) return;
            }

            uintptr_t h1 = 0, h2 = 0;
            memcpy(&h1, block + off.HealthChain1, sizeof(uintptr_t));
            if (!h1) return;
            h2 = mem->Read<uintptr_t>(h1 + off.HealthChain2);
            if (!h2) return;

            float hp    = mem->Read<float>(h2 + off.Health);
            float hpMax = mem->Read<float>(h2 + off.MaxHealth);
            if (!(hpMax > 1.f && hpMax < 10000.f)) return;
            if (!(hp > 0.f && hp <= hpMax)) return;
            st.candidates++;

            Vec3 vel;
            auto it = prevPositions.find(ent);
            if (it != prevPositions.end()) {
                double dtv = now - it->second.second;
                if (dtv > 0.0005 && dtv < 0.5)
                    vel = (pos - it->second.first) * (float)(1.0 / dtv);
                if (vel.Length() > 120.f) vel = vel * (120.f / vel.Length());
            }
            prevPositions[ent] = { pos, now };

            PlayerEntity p;
            p.address    = ent;
            p.feet       = pos;
            p.velocity   = vel;
            p.health     = hp;
            p.maxHealth  = hpMax;
            p.distance   = dist;
            p.isLocal    = local;
            p.isTeammate = (!local && st.localFaction != 0 && faction == st.localFaction);

            if (faction && off.FactionKey) {
                uintptr_t keyPtr = mem->Read<uintptr_t>(faction + off.FactionKey);
                if (keyPtr) p.factionKey = mem->ReadString(keyPtr, 24);
            }

            Vec3 head = pos + Vec3(0.f, 0.f, aimHeight);
            p.onScreen = WorldToScreen(st.camera, head, p.headScreen, w, h);
            if (p.onScreen) WorldToScreen(st.camera, pos, p.feetScreen, w, h);

            if (!local && dist <= skeletonMaxDistance) ReadSkeleton(st, p, block, w, h);

            p.aimWorld    = p.headBoneOk ? p.headBoneWorld : head;
            p.aimOnScreen = WorldToScreen(st.camera, p.aimWorld, p.aimScreen, w, h);
            if (p.aimOnScreen) {
                float dx = p.aimScreen.x - cx, dy = p.aimScreen.y - cy;
                p.crosshairDist = sqrtf(dx * dx + dy * dy);
            }

            st.players.push_back(std::move(p));
        };

        for (int i = 0; i < count; ++i) {
            uintptr_t ent = ptrs[(size_t)i];
            if (!ent || ent < 0x10000) continue;
            if (ent == st.localEntity) {
                if (showLocal) consider(ent, true);
                continue;
            }
            st.rawEntities.push_back(ent);
            consider(ent, false);
        }

        std::sort(st.players.begin(), st.players.end(),
                  [](const PlayerEntity& a, const PlayerEntity& b) {
                      return a.distance < b.distance;
                  });

        if (prevPositions.size() > (size_t)(maxEntities * 4)) prevPositions.clear();
    }
};

// ===========================================================================
//  globals
// ===========================================================================
static Overlay g_overlay;
static Config  g_cfg;
static Offsets g_off;
static Game    g_game;
static bool    g_showMenu = true;
static bool    g_keyState[256] = {};

static double Now() {
    static LARGE_INTEGER freq = [] { LARGE_INTEGER f; QueryPerformanceFrequency(&f); return f; }();
    LARGE_INTEGER c; QueryPerformanceCounter(&c);
    return (double)c.QuadPart / (double)freq.QuadPart;
}

static float RandFloat(float a, float b) {
    return a + (b - a) * ((float)rand() / (float)RAND_MAX);
}

static bool KeyPressed(int vk) {
    bool down = (GetAsyncKeyState(vk) & 0x8000) != 0;
    bool fired = down && !g_keyState[vk];
    g_keyState[vk] = down;
    return fired;
}

static std::wstring ToWide(const std::string& s) {
    if (s.empty()) return L"";
    int n = MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), nullptr, 0);
    std::wstring out((size_t)n, L'\0');
    MultiByteToWideChar(CP_UTF8, 0, s.c_str(), (int)s.size(), out.data(), n);
    return out;
}

static std::string ExeDir() {
    char buf[MAX_PATH] = {};
    GetModuleFileNameA(nullptr, buf, MAX_PATH);
    std::string p(buf);
    size_t s = p.find_last_of("\\/");
    return (s == std::string::npos) ? std::string(".\\") : p.substr(0, s + 1);
}

struct EnumCtx { DWORD pid; HWND hwnd; };

static BOOL CALLBACK EnumProc(HWND h, LPARAM lp) {
    auto* ctx = reinterpret_cast<EnumCtx*>(lp);
    DWORD wpid = 0;
    GetWindowThreadProcessId(h, &wpid);
    if (wpid != ctx->pid) return TRUE;
    if (!IsWindowVisible(h)) return TRUE;
    if (GetWindow(h, GW_OWNER) != nullptr) return TRUE;
    RECT r{};
    GetClientRect(h, &r);
    if (r.right < 200 || r.bottom < 200) return TRUE;
    ctx->hwnd = h;
    return FALSE;
}

static HWND FindGameWindow(DWORD pid) {
    EnumCtx ctx{ pid, nullptr };
    EnumWindows(EnumProc, reinterpret_cast<LPARAM>(&ctx));
    return ctx.hwnd;
}

// ===========================================================================
//  drawing
// ===========================================================================
static void DrawSkeleton(const PlayerEntity& p, COLORREF col) {
    for (int i = 0; i < kBonePairCount; ++i) {
        const int a = kBonePairs[i].a, b = kBonePairs[i].b;
        if (a >= kMaxBones || b >= kMaxBones) continue;
        if (!p.boneOk[a] || !p.boneOk[b]) continue;
        g_overlay.Line(p.boneScreen[a].x, p.boneScreen[a].y,
                       p.boneScreen[b].x, p.boneScreen[b].y, col, 1);
    }
    if (p.headBoneOk)
        g_overlay.Circle(p.boneScreen[g_off.HeadBone].x,
                         p.boneScreen[g_off.HeadBone].y, 3.f, col, 1);
}

static void DrawEsp(const GameState& st) {
    if (!g_cfg.espEnabled) return;

    const int w = g_overlay.Width(), h = g_overlay.Height();
    const float cx = w * 0.5f, cy = h * 0.5f;

    if (g_cfg.fovCircle && g_cfg.aimEnabled)
        g_overlay.Circle(cx, cy, g_cfg.aimFov, g_cfg.colFov, 1);

    for (const auto& p : st.players) {
        const bool mate = g_cfg.teamCheck && p.isTeammate;
        if (mate && g_cfg.hideTeammates) continue;
        if (!p.onScreen) continue;

        const COLORREF accent = (mate && g_cfg.colorTeammates) ? g_cfg.colTeam : g_cfg.colBox;

        if (g_cfg.skeleton && p.headBoneOk) DrawSkeleton(p, g_cfg.colSkeleton);

        float bh = fabsf(p.feetScreen.y - p.headScreen.y);
        if (bh < 3.f) bh = 3.f;
        if (bh > h * 2.5f) bh = h * 2.5f;

        const float bw = bh * 0.55f;
        const float bx = (p.headScreen.x + p.feetScreen.x) * 0.5f - bw * 0.5f;
        const float by = p.headScreen.y;

        if (g_cfg.boxEsp) g_overlay.Rect(bx, by, bw, bh, accent, 1);

        if (g_cfg.healthBar && p.maxHealth > 0.f) {
            float frac = p.health / p.maxHealth;
            if (frac < 0.f) frac = 0.f;
            if (frac > 1.f) frac = 1.f;
            const float barX = bx - 6.f;
            g_overlay.FillRect(barX, by, 3.f, bh, RGB(45, 45, 45));
            g_overlay.FillRect(barX, by + bh * (1.f - frac), 3.f, bh * frac, g_cfg.colHealth);
        }

        if (g_cfg.showDistance) {
            wchar_t buf[32];
            swprintf_s(buf, L"%dm", (int)p.distance);
            g_overlay.Text(bx + bw * 0.5f, by + bh + 2.f, buf,
                           g_cfg.colDist, g_cfg.fontSize, true, true);
        }

        if (g_cfg.showNames && !p.name.empty())
            g_overlay.Text(bx + bw * 0.5f, by - g_cfg.fontSize - 4.f, ToWide(p.name),
                           accent, g_cfg.fontSize, true, true);

        if (g_cfg.snaplines)
            g_overlay.Line(cx, (float)h, bx + bw * 0.5f, by + bh, accent, 1);
    }
}

static void DrawMenu(const GameState& st) {
    if (!g_showMenu) return;

    auto onoff = [](bool b) { return b ? L"ON " : L"OFF"; };

    std::vector<std::wstring> lines;
    lines.push_back(L"REFORGER EXTERNAL");
    lines.push_back(L"----------------------------------");
    lines.push_back(std::wstring(L"[F1]  ESP             ") + onoff(g_cfg.espEnabled));
    lines.push_back(std::wstring(L"[F2]  Box             ") + onoff(g_cfg.boxEsp));
    lines.push_back(std::wstring(L"[F3]  Snaplines       ") + onoff(g_cfg.snaplines));
    lines.push_back(std::wstring(L"[F4]  Names           ") + onoff(g_cfg.showNames));
    lines.push_back(std::wstring(L"[F5]  Health bar      ") + onoff(g_cfg.healthBar));
    lines.push_back(std::wstring(L"[F6]  Distance        ") + onoff(g_cfg.showDistance));
    lines.push_back(std::wstring(L"[F7]  Aimbot          ") + onoff(g_cfg.aimEnabled));
    lines.push_back(std::wstring(L"[F8]  FOV circle      ") + onoff(g_cfg.fovCircle));
    lines.push_back(std::wstring(L"[F9]  Humanize        ") + onoff(g_cfg.humanize));
    lines.push_back(std::wstring(L"[F10] Lead prediction ") + onoff(g_cfg.predict));
    lines.push_back(std::wstring(L"[F11] Skeleton        ") + onoff(g_cfg.skeleton));
    lines.push_back(std::wstring(L"[F12] Team check      ") + onoff(g_cfg.teamCheck));
    lines.push_back(L"[HOME] Find faction offset  [INS] Hide  [END] Quit");
    lines.push_back(L"----------------------------------");

    wchar_t buf[192];
    swprintf_s(buf, L"entities %d | candidates %d | players %d",
               st.entityCount, st.candidates, (int)st.players.size());
    lines.push_back(buf);

    if (g_off.FactionPointer == 0)
        lines.push_back(L"team: no offset set - press HOME");
    else {
        swprintf_s(buf, L"faction resolved: %s", st.localFaction ? L"yes" : L"NULL - wrong offset");
        lines.push_back(buf);
    }

    lines.push_back(st.status.empty() ? L"status: OK" : st.status);

    float y = 8.f;
    for (auto& l : lines) {
        g_overlay.Text(10.f, y, l, g_cfg.colText, g_cfg.fontSize, false, true);
        y += g_cfg.fontSize + 3.f;
    }

    for (auto& s : st.scanResults) {
        g_overlay.Text(10.f, y, s, g_cfg.colTeam, g_cfg.fontSize, false, true);
        y += g_cfg.fontSize + 3.f;
    }
}


// ===========================================================================
//  aimbot
// ===========================================================================
static void UpdateAimbot(const GameState& st, float dt,
                         Vec2& accum, uintptr_t& lastTarget, Vec2& jitter) {
    if (!st.ok || !st.camera.valid) return;
    if (!(GetAsyncKeyState(g_cfg.aimKey) & 0x8000)) { lastTarget = 0; return; }

    const int w = g_overlay.Width(), h = g_overlay.Height();
    const float cx = w * 0.5f, cy = h * 0.5f;

    const PlayerEntity* best = nullptr;
    float bestD = g_cfg.aimFov;
    for (const auto& p : st.players) {
        if (!p.aimOnScreen || p.isLocal) continue;
        if (g_cfg.teamCheck && p.isTeammate) continue;
        if (p.crosshairDist < bestD) { bestD = p.crosshairDist; best = &p; }
    }
    if (!best) { lastTarget = 0; return; }

    Vec3 aimWorld = best->aimWorld;
    if (g_cfg.predict)
        aimWorld = aimWorld + best->velocity * (best->distance / g_cfg.bulletSpeed);

    Vec2 target;
    if (!g_game.WorldToScreen(st.camera, aimWorld, target, w, h)) return;

    float dx = target.x - cx;
    float dy = target.y - cy;

    if (g_cfg.humanize) {
        if (best->address != lastTarget) {
            jitter.x = RandFloat(-g_cfg.jitter, g_cfg.jitter);
            jitter.y = RandFloat(-g_cfg.jitter, g_cfg.jitter);
            lastTarget = best->address;
        }
        jitter.x += RandFloat(-0.06f, 0.06f);
        jitter.y += RandFloat(-0.06f, 0.06f);
        if (jitter.x >  g_cfg.jitter) jitter.x =  g_cfg.jitter;
        if (jitter.x < -g_cfg.jitter) jitter.x = -g_cfg.jitter;
        if (jitter.y >  g_cfg.jitter) jitter.y =  g_cfg.jitter;
        if (jitter.y < -g_cfg.jitter) jitter.y = -g_cfg.jitter;
        dx += jitter.x;
        dy += jitter.y;
    }

    if (fabsf(dx) < 0.6f && fabsf(dy) < 0.6f) return;

    float alpha = 1.f - expf(-g_cfg.aimSpeed * dt);
    if (alpha > 1.f) alpha = 1.f;
    if (alpha < 0.f) alpha = 0.f;

    accum.x += dx * alpha * g_cfg.aimScale;
    accum.y += dy * alpha * g_cfg.aimScale;

    LONG ix = (LONG)accum.x, iy = (LONG)accum.y;
    accum.x -= (float)ix;
    accum.y -= (float)iy;
    if (!ix && !iy) return;

    INPUT in = {};
    in.type       = INPUT_MOUSE;
    in.mi.dx      = ix;
    in.mi.dy      = iy;
    in.mi.dwFlags = MOUSEEVENTF_MOVE;
    SendInput(1, &in, sizeof(INPUT));
}

static void HandleHotkeys() {
    if (KeyPressed(VK_INSERT)) g_showMenu       = !g_showMenu;
    if (KeyPressed(VK_F1))  g_cfg.espEnabled    = !g_cfg.espEnabled;
    if (KeyPressed(VK_F2))  g_cfg.boxEsp        = !g_cfg.boxEsp;
    if (KeyPressed(VK_F3))  g_cfg.snaplines     = !g_cfg.snaplines;
    if (KeyPressed(VK_F4))  g_cfg.showNames     = !g_cfg.showNames;
    if (KeyPressed(VK_F5))  g_cfg.healthBar     = !g_cfg.healthBar;
    if (KeyPressed(VK_F6))  g_cfg.showDistance  = !g_cfg.showDistance;
    if (KeyPressed(VK_F7))  g_cfg.aimEnabled    = !g_cfg.aimEnabled;
    if (KeyPressed(VK_F8))  g_cfg.fovCircle     = !g_cfg.fovCircle;
    if (KeyPressed(VK_F9))  g_cfg.humanize      = !g_cfg.humanize;
    if (KeyPressed(VK_F10)) g_cfg.predict       = !g_cfg.predict;
    if (KeyPressed(VK_F11)) g_cfg.skeleton      = !g_cfg.skeleton;
    if (KeyPressed(VK_F12)) g_cfg.teamCheck     = !g_cfg.teamCheck;
}

// ===========================================================================
//  entry
// ===========================================================================
int WINAPI wWinMain(HINSTANCE, HINSTANCE, LPWSTR, int) {
    SetProcessDpiAwarenessContext(DPI_AWARENESS_CONTEXT_PER_MONITOR_AWARE_V2);
    srand((unsigned)GetTickCount64());

    const std::string dir     = ExeDir();
    const std::string cfgPath = dir + "config.ini";
    const std::string offPath = dir + "offsets.ini";

    LoadOffsets(offPath.c_str(), g_off);
    SaveOffsets(offPath.c_str(), g_off);
    LoadConfig(cfgPath.c_str(), g_cfg);
    SaveConfig(cfgPath.c_str(), g_cfg);

    Memory mem;
    if (!mem.Attach()) {
        std::wstring msg = L"Could not attach to Arma Reforger.\n\n";
        if (!mem.lastError.empty()) msg += mem.lastError + L"\n\n";
        if (!mem.seenProcesses.empty()) {
            msg += L"ArmaReforger* processes seen:\n";
            for (const auto& s : mem.seenProcesses) msg += L"   " + s + L"\n";
        } else {
            msg += L"No ArmaReforger* process is running.\n";
        }
        msg += L"\nStart the game first, then run this as Administrator.";
        MessageBoxW(nullptr, msg.c_str(), L"Reforger External", MB_ICONINFORMATION);
        return 0;
    }

    if (!g_overlay.Create()) {
        MessageBoxA(nullptr, "Failed to create overlay window.", "Reforger External", MB_ICONERROR);
        return 0;
    }

    g_game.mem = &mem;

    GameState st;
    Vec2 accum{ 0.f, 0.f };
    Vec2 jitter{ 0.f, 0.f };
    uintptr_t lastTarget = 0;
    bool scanRequested = false;
    double last = Now();

    while (true) {
        if (KeyPressed(VK_END)) break;
        if (KeyPressed(VK_HOME)) scanRequested = true;

        if (!mem.Alive()) {
            mem.Detach();
            if (!mem.Attach()) { Sleep(500); continue; }
            g_game.mem = &mem;
        }

        const double now = Now();
        float dt = (float)(now - last);
        last = now;
        if (dt > 0.25f) dt = 0.25f;
        if (dt <= 0.f)  dt = 1.f / 240.f;

        HWND gameWnd = FindGameWindow(mem.pid);
        if (!gameWnd) { Sleep(150); continue; }

        RECT cr{};
        GetClientRect(gameWnd, &cr);
        POINT tl{ 0, 0 };
        ClientToScreen(gameWnd, &tl);
        g_overlay.SetBounds(tl.x, tl.y, cr.right, cr.bottom);

        HandleHotkeys();

        g_game.off                 = g_off;
        g_game.maxDistance         = g_cfg.maxDistance;
        g_game.aimHeight           = g_cfg.aimHeight;
        g_game.maxEntities         = g_cfg.maxEntities;
        g_game.showLocal           = g_cfg.showLocal;
        g_game.teamCheck           = g_cfg.teamCheck;
        g_game.skeletonMaxDistance = g_cfg.skeletonMaxDistance;
        g_game.skeletonMaxCount    = g_cfg.skeletonMaxCount;

        g_game.Update(st, g_overlay.Width(), g_overlay.Height(), now);

        if (scanRequested && st.ok) { g_game.RunFactionScan(st); scanRequested = false; }

        g_overlay.Begin();
        DrawEsp(st);
        if (GetForegroundWindow() == gameWnd)
            UpdateAimbot(st, dt, accum, lastTarget, jitter);
        DrawMenu(st);
        g_overlay.Present();

        Sleep(1);
    }

    SaveConfig(cfgPath.c_str(), g_cfg);
    SaveOffsets(offPath.c_str(), g_off);
    g_overlay.Destroy();
    mem.Detach();
    return 0;
}
