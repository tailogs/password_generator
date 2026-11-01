// password_generator.c — cryptographically secure password generator with hardening
// Build (MSVC):   cl password_generator.c /link user32.lib gdi32.lib shell32.lib bcrypt.lib
// Build (MinGW):  gcc password_generator.c -o password_generator.exe -lbcrypt -luser32 -lgdi32 -lshell32 -mwindows

#ifndef _WIN32_WINNT
#define _WIN32_WINNT 0x0602   /* Win8+ для SetProcessMitigationPolicy */
#endif
#include <windows.h>
#include <bcrypt.h>
#include <limits.h>
#include <stdlib.h>
#include <shellapi.h>
#include <string.h>
#include "resource.h"

#ifdef _MSC_VER
#pragma comment(lib, "bcrypt.lib")
#endif

#ifndef WDA_EXCLUDEFROMCAPTURE
#define WDA_EXCLUDEFROMCAPTURE 0x00000011
#endif
/* Новые ID. Добавьте их в resource.h — или оставьте как есть, работают через #ifndef */
#ifndef ID_CLEAR_BTN
#define ID_CLEAR_BTN          2001
#endif
#ifndef ID_MASK_CHK
#define ID_MASK_CHK           2002
#endif
#ifndef ID_CLEAR_ON_COPY_CHK
#define ID_CLEAR_ON_COPY_CHK  2003
#endif

#define VERSION_STR  "1.0.0"
#define VERSION_WSTR L"1.0.0"

#define MIN_PASSWORD_LEN      4
#define MAX_PASSWORD_LEN      128

#define TIMER_COPY_FEEDBACK   1
#define TIMER_CLIPBOARD_CLEAR 2
#define TIMER_FIELD_CLEAR     3

#define CLIPBOARD_CLEAR_MS    30000   /* 30 секунд */
#define FIELD_CLEAR_MS        5000    /* 5 секунд после копирования */

#define BG_COLOR        RGB(30, 30, 30)
#define TEXT_COLOR      RGB(255, 255, 255)
#define TEXT_DARK       RGB(0, 0, 0)
#define BTN_BG_COLOR    RGB(75, 75, 75)
#define BTN_BG_HOVER    RGB(200, 200, 200)
#define BTN_BG_PRESSED  RGB(150, 150, 150)

static const char LOWERCASE_CHARS[] = "abcdefghijklmnopqrstuvwxyz";
static const char UPPERCASE_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
static const char DIGIT_CHARS[]     = "0123456789";
static const char SYMBOL_CHARS[]    = "!@#$%^&*()-_=+[]{}|;:,.<>?/~`";

static HWND   hLengthEdit, hGenerateBtn, hLowercaseChk, hUppercaseChk;
static HWND   hDigitsChk, hSymbolsChk, hPasswordText, hCopyBtn, hClearBtn;
static HWND   hMaskChk, hClearOnCopyChk;
static HFONT  hFont;
static HBRUSH hBgBrush;
static NOTIFYICONDATA nid;
static BOOL   isMouseOverGenerateBtn, isMouseOverCopyBtn, isMouseOverClearBtn;
static WNDPROC oldGenerateBtnProc, oldCopyBtnProc, oldClearBtnProc;

/* SHA-256 от того, что мы положили в клипборд.
   Используется, чтобы очищать буфер, только если в нём всё ещё НАШ пароль. */
static unsigned char g_clipboardHash[32];
static BOOL          g_clipboardHashValid = FALSE;

/* ---------- Forward decl ---------- */
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
static LRESULT CALLBACK ButtonProc(HWND, UINT, WPARAM, LPARAM);
static void GeneratePassword(HWND);
static void CopyPassword(HWND);
static void WipePasswordField(void);
static void WipeAllSensitiveState(HWND, BOOL);
static void ClearClipboardIfOurs(HWND, BOOL);
static void ShowAboutDialog(HWND);

/* =================== CSPRNG (без modulo bias) =================== */
static BOOL SecureRandomInt(int max, int *out) {
    unsigned int bound, r;
    if (max <= 0) return FALSE;
    bound = UINT_MAX - (UINT_MAX % (unsigned int)max);
    do {
        if (BCryptGenRandom(NULL, (PUCHAR)&r, sizeof(r),
                            BCRYPT_USE_SYSTEM_PREFERRED_RNG) != 0)
            return FALSE;
    } while (r >= bound);
    *out = (int)(r % (unsigned int)max);
    return TRUE;
}

/* =================== SHA-256 для верификации клипборда =================== */
static BOOL ComputeSha256(const void *data, size_t len, unsigned char out[32]) {
    BCRYPT_ALG_HANDLE  hAlg  = NULL;
    BCRYPT_HASH_HANDLE hHash = NULL;
    PUCHAR hashObj = NULL;
    DWORD  hashObjSize = 0, cbResult = 0;
    BOOL ok = FALSE;

    if (BCryptOpenAlgorithmProvider(&hAlg, BCRYPT_SHA256_ALGORITHM, NULL, 0) != 0)
        return FALSE;
    if (BCryptGetProperty(hAlg, BCRYPT_OBJECT_LENGTH,
                          (PUCHAR)&hashObjSize, sizeof(hashObjSize), &cbResult, 0) != 0)
        goto done;
    hashObj = (PUCHAR)HeapAlloc(GetProcessHeap(), 0, hashObjSize);
    if (!hashObj) goto done;
    if (BCryptCreateHash(hAlg, &hHash, hashObj, hashObjSize, NULL, 0, 0) != 0) goto done;
    if (BCryptHashData(hHash, (PUCHAR)data, (ULONG)len, 0) != 0) goto done;
    if (BCryptFinishHash(hHash, out, 32, 0) != 0) goto done;
    ok = TRUE;
done:
    if (hHash)   BCryptDestroyHash(hHash);
    if (hashObj) HeapFree(GetProcessHeap(), 0, hashObj);
    if (hAlg)    BCryptCloseAlgorithmProvider(hAlg, 0);
    return ok;
}

/* =================== Secure buffer (VirtualLock) =================== */
typedef struct { char *data; SIZE_T size; BOOL locked; } SecureBuf;

static BOOL SecureBufAlloc(SecureBuf *sb, SIZE_T size) {
    sb->data = (char *)VirtualAlloc(NULL, size, MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!sb->data) return FALSE;
    sb->size   = size;
    sb->locked = VirtualLock(sb->data, size);
    return TRUE;
}
static void SecureBufFree(SecureBuf *sb) {
    if (sb->data) {
        SecureZeroMemory(sb->data, sb->size);
        if (sb->locked) VirtualUnlock(sb->data, sb->size);
        VirtualFree(sb->data, 0, MEM_RELEASE);
        sb->data = NULL; sb->size = 0; sb->locked = FALSE;
    }
}

/* =================== Privacy-форматы клипборда =================== */
static void SetClipboardPrivacyFormats(void) {
    static const char *formats[] = {
        "ExcludeClipboardContentFromMonitorProcessing",
        "CanIncludeInClipboardHistory",
        "CanUploadToCloudClipboard"
    };
    int i;
    for (i = 0; i < 3; i++) {
        UINT fmt = RegisterClipboardFormatA(formats[i]);
        HGLOBAL hMem;
        DWORD  *p;
        if (!fmt) continue;
        hMem = GlobalAlloc(GMEM_MOVEABLE | GMEM_ZEROINIT, sizeof(DWORD));
        if (!hMem) continue;
        p = (DWORD *)GlobalLock(hMem);
        if (p) {
            *p = 0;
            GlobalUnlock(hMem);
            if (!SetClipboardData(fmt, hMem)) GlobalFree(hMem);
        } else {
            GlobalFree(hMem);
        }
    }
}

/* =================== Очистка клипборда с проверкой =================== */
static void ClearClipboardIfOurs(HWND hwnd, BOOL allowRetry) {
    BOOL wasOurs = FALSE;
    if (!g_clipboardHashValid) return;

    if (!OpenClipboard(hwnd)) {
        if (allowRetry) SetTimer(hwnd, TIMER_CLIPBOARD_CLEAR, 2000, NULL);
        return;
    }

    {
        HANDLE hData = GetClipboardData(CF_TEXT);
        if (hData) {
            const char *text = (const char *)GlobalLock(hData);
            if (text) {
                unsigned char hash[32];
                if (ComputeSha256(text, strlen(text), hash) &&
                    memcmp(hash, g_clipboardHash, 32) == 0) {
                    wasOurs = TRUE;
                }
                GlobalUnlock(hData);
            }
        }
    }
    if (wasOurs) EmptyClipboard();
    CloseClipboard();

    /* Наш пароль больше не в буфере (стёрт или заменён). Хэш не нужен. */
    SecureZeroMemory(g_clipboardHash, sizeof(g_clipboardHash));
    g_clipboardHashValid = FALSE;
}

/* =================== Стирание поля пароля =================== */
static void WipePasswordField(void) {
    int len;
    if (!hPasswordText) return;
    len = GetWindowTextLengthA(hPasswordText);
    if (len > 0) {
        /* Перезаписываем filler’ом, чтобы уменьшить шанс остатков в heap */
        char filler[256];
        int n = len < (int)sizeof(filler) - 1 ? len : (int)sizeof(filler) - 1;
        memset(filler, 'X', n);
        filler[n] = 0;
        SetWindowTextA(hPasswordText, filler);
        SecureZeroMemory(filler, sizeof(filler));
    }
    SetWindowTextA(hPasswordText, "");
}

/* =================== Полная зачистка (скрытие/выход) =================== */
static void WipeAllSensitiveState(HWND hwnd, BOOL allowRetry) {
    KillTimer(hwnd, TIMER_CLIPBOARD_CLEAR);
    KillTimer(hwnd, TIMER_FIELD_CLEAR);
    ClearClipboardIfOurs(hwnd, allowRetry);
    WipePasswordField();
}

/* =================== Process hardening =================== */
static void HardenProcess(void) {
    HMODULE k32;
    typedef BOOL (WINAPI *PFN_SPMP)(PROCESS_MITIGATION_POLICY, PVOID, SIZE_T);
    PFN_SPMP pSet;
    FARPROC  raw;

    k32 = GetModuleHandleA("kernel32.dll");
    if (!k32) return;
    raw = GetProcAddress(k32, "SetProcessMitigationPolicy");
    if (!raw) return;
    /* Каст через void* — стандартный способ подавить -Wcast-function-type */
    pSet = (PFN_SPMP)(void *)raw;

    {
        PROCESS_MITIGATION_EXTENSION_POINT_DISABLE_POLICY epPolicy;
        memset(&epPolicy, 0, sizeof(epPolicy));
        epPolicy.DisableExtensionPoints = 1;
        pSet(ProcessExtensionPointDisablePolicy, &epPolicy, sizeof(epPolicy));
    }
}

/* =================== Hover-эффект для owner-draw кнопок =================== */
static LRESULT CALLBACK ButtonProc(HWND hwnd, UINT msg, WPARAM wParam, LPARAM lParam) {
    WNDPROC oldProc = (hwnd == hGenerateBtn) ? oldGenerateBtnProc :
                      (hwnd == hCopyBtn)     ? oldCopyBtnProc    :
                                                oldClearBtnProc;
    BOOL *flag = (hwnd == hGenerateBtn) ? &isMouseOverGenerateBtn :
                 (hwnd == hCopyBtn)     ? &isMouseOverCopyBtn    :
                                          &isMouseOverClearBtn;

    switch (msg) {
    case WM_MOUSEMOVE: {
        TRACKMOUSEEVENT tme = { sizeof(tme), TME_LEAVE, hwnd, 0 };
        TrackMouseEvent(&tme);
        if (!*flag) { *flag = TRUE; InvalidateRect(hwnd, NULL, TRUE); }
        break;
    }
    case WM_MOUSELEAVE:
        if (*flag) { *flag = FALSE; InvalidateRect(hwnd, NULL, TRUE); }
        break;
    }
    return CallWindowProc(oldProc, hwnd, msg, wParam, lParam);
}

/* =================== WinMain =================== */
int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance,
                   LPSTR lpCmdLine, int nCmdShow) {
    WNDCLASSEX wcex = { 0 };
    HWND hwnd;
    HMENU hMenu;
    int winW = 420, winH = 265;
    int x, y;

    (void)hPrevInstance; (void)lpCmdLine;

    { HWND c = GetConsoleWindow(); if (c) ShowWindow(c, SW_HIDE); }

    HardenProcess();

    wcex.cbSize        = sizeof(WNDCLASSEX);
    wcex.style         = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc   = WndProc;
    wcex.hInstance     = hInstance;
    wcex.hCursor       = LoadCursor(NULL, IDC_ARROW);
    hBgBrush           = CreateSolidBrush(BG_COLOR);
    wcex.hbrBackground = hBgBrush;
    wcex.lpszClassName = "PasswordClass";
    wcex.hIcon         = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1));
    wcex.hIconSm       = wcex.hIcon;
    if (!RegisterClassEx(&wcex)) return FALSE;

    x = (GetSystemMetrics(SM_CXSCREEN) - winW) / 2;
    y = (GetSystemMetrics(SM_CYSCREEN) - winH) / 2;

    hwnd = CreateWindow("PasswordClass", "Password Generator",
        (WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX) | WS_VISIBLE,
        x, y, winW, winH, NULL, NULL, hInstance, NULL);
    if (!hwnd) return FALSE;

    /* Анти-скриншот: окно не попадает в захват экрана и превью таскбара */
    if (!SetWindowDisplayAffinity(hwnd, WDA_EXCLUDEFROMCAPTURE))
        SetWindowDisplayAffinity(hwnd, WDA_MONITOR);

    hMenu = LoadMenu(hInstance, MAKEINTRESOURCE(IDR_MYMENU));
    if (hMenu) SetMenu(hwnd, hMenu);

    /* --- Контролы --- */
    hGenerateBtn = CreateWindow("BUTTON", "Generate",
        WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | BS_OWNERDRAW,
        10, 10, 140, 30, hwnd, (HMENU)ID_GENERATE_BTN, hInstance, NULL);
    hLowercaseChk = CreateWindow("BUTTON", "Lower case",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        10, 50, 140, 30, hwnd, (HMENU)ID_LOWERCASE_CHK, hInstance, NULL);
    hUppercaseChk = CreateWindow("BUTTON", "Upper letters",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        10, 80, 140, 30, hwnd, (HMENU)ID_UPPERCASE_CHK, hInstance, NULL);
    hDigitsChk = CreateWindow("BUTTON", "Numbers",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        10, 110, 140, 30, hwnd, (HMENU)ID_DIGITS_CHK, hInstance, NULL);
    hSymbolsChk = CreateWindow("BUTTON", "Symbols",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        10, 140, 140, 30, hwnd, (HMENU)ID_SYMBOLS_CHK, hInstance, NULL);

    CreateWindow("STATIC", "Length", WS_CHILD | WS_VISIBLE,
        160, 52, 45, 20, hwnd, NULL, hInstance, NULL);

    hLengthEdit = CreateWindow("EDIT", "16",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_NUMBER,
        210, 50, 55, 25, hwnd, (HMENU)ID_LENGTH_EDIT, hInstance, NULL);
    SendMessage(hLengthEdit, EM_SETLIMITTEXT, 3, 0);

    hMaskChk = CreateWindow("BUTTON", "Mask password",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        160, 85, 140, 20, hwnd, (HMENU)ID_MASK_CHK, hInstance, NULL);
    hClearOnCopyChk = CreateWindow("BUTTON", "Clear field after copy",
        WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        160, 110, 140, 20, hwnd, (HMENU)ID_CLEAR_ON_COPY_CHK, hInstance, NULL);

    hPasswordText = CreateWindow("EDIT", "",
        WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | ES_READONLY,
        10, 180, 245, 25, hwnd, (HMENU)ID_PASSWORD_TEXT, hInstance, NULL);
    hCopyBtn = CreateWindow("BUTTON", "Copy",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_OWNERDRAW,
        260, 180, 65, 25, hwnd, (HMENU)ID_COPY_BTN, hInstance, NULL);
    hClearBtn = CreateWindow("BUTTON", "Clear",
        WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_OWNERDRAW,
        330, 180, 65, 25, hwnd, (HMENU)ID_CLEAR_BTN, hInstance, NULL);

    /* --- Шрифт --- */
    hFont = CreateFont(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
                       OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
                       DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");
    {
        HWND all[] = {
            hGenerateBtn, hLowercaseChk, hUppercaseChk, hDigitsChk,
            hSymbolsChk, hLengthEdit, hPasswordText, hCopyBtn, hClearBtn,
            hMaskChk, hClearOnCopyChk
        };
        int i;
        for (i = 0; i < (int)(sizeof(all)/sizeof(all[0])); i++)
            SendMessage(all[i], WM_SETFONT, (WPARAM)hFont, TRUE);
    }

    SendMessage(hLowercaseChk,    BM_SETCHECK, BST_CHECKED, 0);
    SendMessage(hUppercaseChk,    BM_SETCHECK, BST_CHECKED, 0);
    SendMessage(hDigitsChk,       BM_SETCHECK, BST_CHECKED, 0);
    SendMessage(hClearOnCopyChk,  BM_SETCHECK, BST_CHECKED, 0);

    oldGenerateBtnProc = (WNDPROC)SetWindowLongPtr(hGenerateBtn, GWLP_WNDPROC, (LONG_PTR)ButtonProc);
    oldCopyBtnProc     = (WNDPROC)SetWindowLongPtr(hCopyBtn,     GWLP_WNDPROC, (LONG_PTR)ButtonProc);
    oldClearBtnProc    = (WNDPROC)SetWindowLongPtr(hClearBtn,    GWLP_WNDPROC, (LONG_PTR)ButtonProc);

    /* --- Трей --- */
    ZeroMemory(&nid, sizeof(nid));
    nid.cbSize           = sizeof(nid);
    nid.hWnd             = hwnd;
    nid.uID              = 1;
    nid.uFlags           = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.hIcon            = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1));
    nid.uCallbackMessage = WM_USER + 1;
    lstrcpynA(nid.szTip, "Password Generator",
              (int)(sizeof(nid.szTip) / sizeof(nid.szTip[0])));
    Shell_NotifyIcon(NIM_ADD, &nid);

    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    {
        MSG msg;
        while (GetMessage(&msg, NULL, 0, 0)) {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }
        return (int)msg.wParam;
    }
}

/* =================== WndProc =================== */
LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {

    case WM_COMMAND:
        switch (LOWORD(wParam)) {
        case ID_GENERATE_BTN: GeneratePassword(hwnd); return 0;
        case ID_COPY_BTN:     CopyPassword(hwnd);     return 0;
        case ID_CLEAR_BTN:
            WipeAllSensitiveState(hwnd, TRUE);
            return 0;
        case ID_MASK_CHK:
            if (HIWORD(wParam) == BN_CLICKED) {
                BOOL checked = SendMessage(hMaskChk, BM_GETCHECK, 0, 0) == BST_CHECKED;
                SendMessage(hPasswordText, EM_SETPASSWORDCHAR, checked ? (WPARAM)'*' : 0, 0);
                InvalidateRect(hPasswordText, NULL, TRUE);
            }
            return 0;
        case ID_FILE_EXIT:
            Shell_NotifyIcon(NIM_DELETE, &nid);
            PostQuitMessage(0);
            return 0;
        case ID_TRAY_SHOW:
            ShowWindow(hwnd, SW_RESTORE);
            SetForegroundWindow(hwnd);
            return 0;
        case ID_HELP_ABOUT:   ShowAboutDialog(hwnd);  return 0;
        }
        break;

    case WM_USER + 1:
        if (lParam == WM_RBUTTONUP) {
            HMENU hMenu = CreatePopupMenu();
            AppendMenu(hMenu, MF_STRING, ID_TRAY_SHOW, "Show");
            AppendMenu(hMenu, MF_STRING, ID_FILE_EXIT, "Exit");
            { POINT pt; GetCursorPos(&pt); SetForegroundWindow(hwnd);
              TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL); }
            DestroyMenu(hMenu);
        } else if (lParam == WM_LBUTTONDBLCLK) {
            ShowWindow(hwnd, SW_RESTORE);
            SetForegroundWindow(hwnd);
        }
        return 0;

    case WM_DRAWITEM: {
        LPDRAWITEMSTRUCT pDIS = (LPDRAWITEMSTRUCT)lParam;
        if (pDIS->CtlID == ID_GENERATE_BTN ||
            pDIS->CtlID == ID_COPY_BTN     ||
            pDIS->CtlID == ID_CLEAR_BTN) {

            BOOL isMouseOver =
                (pDIS->CtlID == ID_GENERATE_BTN) ? isMouseOverGenerateBtn :
                (pDIS->CtlID == ID_COPY_BTN)     ? isMouseOverCopyBtn     :
                                                   isMouseOverClearBtn;
            BOOL      darkText = FALSE;
            COLORREF  bg;

            if (pDIS->itemState & ODS_SELECTED) { bg = BTN_BG_PRESSED; darkText = TRUE; }
            else if (isMouseOver)              { bg = BTN_BG_HOVER;   darkText = TRUE; }
            else                                { bg = BTN_BG_COLOR; }

            { HBRUSH hb = CreateSolidBrush(bg);
              FillRect(pDIS->hDC, &pDIS->rcItem, hb);
              DeleteObject(hb); }

            SetBkMode(pDIS->hDC, TRANSPARENT);
            SetTextColor(pDIS->hDC, darkText ? TEXT_DARK : TEXT_COLOR);
            { char text[256];
              GetWindowTextA(pDIS->hwndItem, text, sizeof(text));
              DrawTextA(pDIS->hDC, text, -1, &pDIS->rcItem,
                        DT_CENTER | DT_VCENTER | DT_SINGLELINE); }

            if (pDIS->itemState & ODS_FOCUS) {
                RECT rc = pDIS->rcItem;
                InflateRect(&rc, -3, -3);
                DrawFocusRect(pDIS->hDC, &rc);
            }
            return TRUE;
        }
        break;
    }

    case WM_CTLCOLORSTATIC: {
        HDC hdc = (HDC)wParam;
        SetBkMode(hdc, TRANSPARENT);
        SetTextColor(hdc, TEXT_COLOR);
        return (INT_PTR)hBgBrush;
    }
    case WM_CTLCOLOREDIT: {
        HDC hdc = (HDC)wParam;
        SetBkColor(hdc, BG_COLOR);
        SetTextColor(hdc, TEXT_COLOR);
        return (INT_PTR)hBgBrush;
    }

    case WM_TIMER:
        if (wParam == TIMER_COPY_FEEDBACK) {
            KillTimer(hwnd, TIMER_COPY_FEEDBACK);
            SetWindowTextA(hCopyBtn, "Copy");
            return 0;
        }
        if (wParam == TIMER_CLIPBOARD_CLEAR) {
            KillTimer(hwnd, TIMER_CLIPBOARD_CLEAR);
            ClearClipboardIfOurs(hwnd, FALSE);
            return 0;
        }
        if (wParam == TIMER_FIELD_CLEAR) {
            KillTimer(hwnd, TIMER_FIELD_CLEAR);
            WipePasswordField();
            return 0;
        }
        break;

    case WM_CLOSE:
        WipeAllSensitiveState(hwnd, FALSE);   /* свернулись в трей — всё стёрли */
        ShowWindow(hwnd, SW_HIDE);
        return 0;

    case WM_DESTROY:
        WipeAllSensitiveState(hwnd, FALSE);
        Shell_NotifyIcon(NIM_DELETE, &nid);
        if (hFont)    DeleteObject(hFont);
        if (hBgBrush) DeleteObject(hBgBrush);
        PostQuitMessage(0);
        return 0;
    }

    return DefWindowProc(hwnd, message, wParam, lParam);
}

/* =================== Генерация =================== */
static void GeneratePassword(HWND hwnd) {
    BOOL useLowercase = SendMessage(hLowercaseChk, BM_GETCHECK, 0, 0) == BST_CHECKED;
    BOOL useUppercase = SendMessage(hUppercaseChk, BM_GETCHECK, 0, 0) == BST_CHECKED;
    BOOL useDigits    = SendMessage(hDigitsChk,    BM_GETCHECK, 0, 0) == BST_CHECKED;
    BOOL useSymbols   = SendMessage(hSymbolsChk,   BM_GETCHECK, 0, 0) == BST_CHECKED;
    SecureBuf sb;
    char *password;
    int length;

    if (!useLowercase && !useUppercase && !useDigits && !useSymbols) {
        MessageBoxW(hwnd,
            L"Выберите хотя бы один тип символов для генерации пароля.",
            L"Ошибка", MB_OK | MB_ICONERROR);
        return;
    }

    { char lengthStr[8] = { 0 };
      GetWindowTextA(hLengthEdit, lengthStr, sizeof(lengthStr));
      length = atoi(lengthStr); }

    if (length < MIN_PASSWORD_LEN || length > MAX_PASSWORD_LEN) {
        wchar_t msg[128];
        wsprintfW(msg, L"Длина пароля должна быть от %d до %d символов.",
                  MIN_PASSWORD_LEN, MAX_PASSWORD_LEN);
        MessageBoxW(hwnd, msg, L"Ошибка", MB_OK | MB_ICONERROR);
        return;
    }

    {
        const char *categories[4];
        int catLens[4];
        int numCategories = 0;

        if (useLowercase) { categories[numCategories] = LOWERCASE_CHARS; catLens[numCategories++] = (int)(sizeof(LOWERCASE_CHARS) - 1); }
        if (useUppercase) { categories[numCategories] = UPPERCASE_CHARS; catLens[numCategories++] = (int)(sizeof(UPPERCASE_CHARS) - 1); }
        if (useDigits)    { categories[numCategories] = DIGIT_CHARS;     catLens[numCategories++] = (int)(sizeof(DIGIT_CHARS) - 1); }
        if (useSymbols)   { categories[numCategories] = SYMBOL_CHARS;    catLens[numCategories++] = (int)(sizeof(SYMBOL_CHARS) - 1); }

        if (length < numCategories) {
            MessageBoxW(hwnd,
                L"Длина пароля слишком мала для выбранных типов символов.",
                L"Ошибка", MB_OK | MB_ICONERROR);
            return;
        }

        if (!SecureBufAlloc(&sb, MAX_PASSWORD_LEN + 1)) {
            MessageBoxW(hwnd, L"Не удалось выделить защищённую память.",
                        L"Ошибка", MB_OK | MB_ICONERROR);
            return;
        }
        password = sb.data;

        {
            char charset[256];
            int  charsetLen = 0;
            BOOL ok = TRUE;
            int  i;

            for (i = 0; i < numCategories; i++) {
                memcpy(charset + charsetLen, categories[i], catLens[i]);
                charsetLen += catLens[i];
            }

            for (i = 0; i < numCategories && ok; i++) {
                int idx;
                ok = SecureRandomInt(catLens[i], &idx);
                if (ok) password[i] = categories[i][idx];
            }
            for (i = numCategories; i < length && ok; i++) {
                int idx;
                ok = SecureRandomInt(charsetLen, &idx);
                if (ok) password[i] = charset[idx];
            }
            for (i = length - 1; i > 0 && ok; i--) {
                int j;
                ok = SecureRandomInt(i + 1, &j);
                if (ok) {
                    char t = password[i];
                    password[i] = password[j];
                    password[j] = t;
                }
            }

            if (ok) {
                password[length] = '\0';
                SetWindowTextA(hPasswordText, password);
                /* Применяем текущее состояние маски */
                if (SendMessage(hMaskChk, BM_GETCHECK, 0, 0) == BST_CHECKED)
                    SendMessage(hPasswordText, EM_SETPASSWORDCHAR, (WPARAM)'*', 0);
                else
                    SendMessage(hPasswordText, EM_SETPASSWORDCHAR, 0, 0);
                InvalidateRect(hPasswordText, NULL, TRUE);
                KillTimer(hwnd, TIMER_FIELD_CLEAR);
            } else {
                MessageBoxW(hwnd,
                    L"Не удалось получить криптографически стойкие случайные числа.",
                    L"Ошибка", MB_OK | MB_ICONERROR);
            }
        }

        SecureBufFree(&sb);
    }
}

/* =================== Копирование с privacy + таймерами =================== */
static void CopyPassword(HWND hwnd) {
    int    len = GetWindowTextLengthA(hPasswordText);
    char  *password;
    HGLOBAL hMemA = NULL, hMemW = NULL;

    if (len <= 0) return;

    password = (char *)VirtualAlloc(NULL, len + 1,
                                    MEM_COMMIT | MEM_RESERVE, PAGE_READWRITE);
    if (!password) return;
    VirtualLock(password, len + 1);
    GetWindowTextA(hPasswordText, password, len + 1);

    hMemA = GlobalAlloc(GMEM_MOVEABLE, len + 1);
    hMemW = GlobalAlloc(GMEM_MOVEABLE, (len + 1) * sizeof(WCHAR));
    if (hMemA && hMemW) {
        char  *pA = (char  *)GlobalLock(hMemA);
        WCHAR *pW = (WCHAR *)GlobalLock(hMemW);
        if (pA && pW) {
            memcpy(pA, password, len + 1);
            MultiByteToWideChar(CP_ACP, 0, password, len + 1, pW, len + 1);
            GlobalUnlock(hMemA);
            GlobalUnlock(hMemW);
            if (OpenClipboard(hwnd)) {
                EmptyClipboard();
                SetClipboardPrivacyFormats();
                if (!SetClipboardData(CF_TEXT,        hMemA)) GlobalFree(hMemA); else hMemA = NULL;
                if (!SetClipboardData(CF_UNICODETEXT, hMemW)) GlobalFree(hMemW); else hMemW = NULL;
                CloseClipboard();
            }
        } else {
            if (pA) GlobalUnlock(hMemA);
            if (pW) GlobalUnlock(hMemW);
        }
    }
    if (hMemA) GlobalFree(hMemA);
    if (hMemW) GlobalFree(hMemW);

    if (ComputeSha256(password, len, g_clipboardHash)) {
        g_clipboardHashValid = TRUE;
        SetTimer(hwnd, TIMER_CLIPBOARD_CLEAR, CLIPBOARD_CLEAR_MS, NULL); /* рестарт */
    }

    SecureZeroMemory(password, len + 1);
    VirtualUnlock(password, len + 1);
    VirtualFree(password, 0, MEM_RELEASE);

    SetWindowTextA(hCopyBtn, "Copied!");
    SetTimer(hwnd, TIMER_COPY_FEEDBACK, 1000, NULL);

    if (SendMessage(hClearOnCopyChk, BM_GETCHECK, 0, 0) == BST_CHECKED)
        SetTimer(hwnd, TIMER_FIELD_CLEAR, FIELD_CLEAR_MS, NULL);
}

static void ShowAboutDialog(HWND hwnd) {
    wchar_t message[640];
    wsprintfW(message,
        L"Password Generator %s\n\n"
        L"Криптографически стойкий генератор паролей.\n\n"
        L"Безопасность:\n"
        L"• BCryptGenRandom (Windows CNG), rejection sampling\n"
        L"• VirtualAlloc + VirtualLock для временных буферов\n"
        L"• SecureZeroMemory после использования\n"
        L"• Privacy-форматы буфера обмена (исключение из истории и облака)\n"
        L"• Автоочистка буфера через 30 с с проверкой SHA-256\n"
        L"• Маскировка поля пароля\n"
        L"• SetWindowDisplayAffinity — защита от скриншотов\n"
        L"• SetProcessMitigationPolicy — запрет AppInit_DLLs и чужих хуков\n"
        L"• Зачистка при скрытии в трей и выходе\n\n"
        L"Разработчик — Taillogs.",
        VERSION_WSTR);
    MessageBoxW(hwnd, message, L"О программе", MB_OK | MB_ICONINFORMATION);
}