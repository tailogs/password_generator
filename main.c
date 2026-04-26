#include <windows.h>
#include <stdio.h>
#include <time.h>
#include <shellapi.h>
#include <stdbool.h>
#include "resource.h"

#define VERSION "0.0.1"

const char LOWERCASE_CHARS[] = "abcdefghijklmnopqrstuvwxyz";
const char UPPERCASE_CHARS[] = "ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const char DIGIT_CHARS[] = "0123456789";
const char SYMBOL_CHARS[] = "!@#$%^&*()_+~`|\\}{[\":?><,./;'";

BOOL InitInstance(HINSTANCE, int);
LRESULT CALLBACK WndProc(HWND, UINT, WPARAM, LPARAM);
void GeneratePassword(HWND);
void CopyPassword(HWND);
void ShowAboutDialog(HWND);

HWND hLengthEdit, hGenerateBtn, hLowercaseChk, hUppercaseChk, hDigitsChk, hSymbolsChk, hPasswordText, hCopyBtn;
HFONT hFont;

NOTIFYICONDATA nid;

BOOL isMouseOverGenerateBtn = FALSE;
BOOL isMouseOverCopyBtn = FALSE;

int WINAPI WinMain(HINSTANCE hInstance, HINSTANCE hPrevInstance, LPSTR lpCmdLine, int nCmdShow) {
    (void)hPrevInstance;
    (void)lpCmdLine;
    HWND myConsole = GetConsoleWindow();
    ShowWindow(myConsole, 0);

    srand((unsigned int)time(NULL));

    WNDCLASSEX wcex = { 0 };
    wcex.cbSize = sizeof(WNDCLASSEX);
    wcex.style = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc = WndProc;
    wcex.hInstance = hInstance;
    wcex.hCursor = LoadCursor(NULL, IDC_ARROW);
    wcex.hbrBackground = CreateSolidBrush(RGB(30, 30, 30)); // <-- добавить
    wcex.lpszClassName = "PasswordClass";
    wcex.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1));
    RegisterClassEx(&wcex);

    HWND hwnd = CreateWindow("PasswordClass", "Password Generator",
        ((WS_OVERLAPPEDWINDOW & ~WS_THICKFRAME & ~WS_MAXIMIZEBOX) | WS_VISIBLE), CW_USEDEFAULT, CW_USEDEFAULT,
        395, 265, NULL, NULL, hInstance, NULL);
        

    if (!hwnd)
        return FALSE;

    HMENU hMenu = LoadMenu(hInstance, MAKEINTRESOURCE(IDR_MYMENU));
        SetMenu(hwnd, hMenu);

    hGenerateBtn = CreateWindow("BUTTON", "Generate", WS_CHILD | WS_VISIBLE | BS_DEFPUSHBUTTON | BS_OWNERDRAW,
        10, 10, 140, 30, hwnd, (HMENU)ID_GENERATE_BTN, hInstance, NULL);

    hLowercaseChk = CreateWindow("BUTTON", "Lower case", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        10, 50, 140, 30, hwnd, (HMENU)ID_LOWERCASE_CHK, hInstance, NULL);

    hUppercaseChk = CreateWindow("BUTTON", "Upper letters", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        10, 80, 140, 30, hwnd, (HMENU)ID_UPPERCASE_CHK, hInstance, NULL);

    hDigitsChk = CreateWindow("BUTTON", "Numbers", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        10, 110, 140, 30, hwnd, (HMENU)ID_DIGITS_CHK, hInstance, NULL);

    hSymbolsChk = CreateWindow("BUTTON", "Symbols", WS_CHILD | WS_VISIBLE | BS_AUTOCHECKBOX,
        10, 140, 140, 30, hwnd, (HMENU)ID_SYMBOLS_CHK, hInstance, NULL);

    hLengthEdit = CreateWindow("EDIT", "8", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_NUMBER,
        160, 50, 40, 25, hwnd, (HMENU)ID_LENGTH_EDIT, hInstance, NULL);

    CreateWindow("STATIC", "Length", WS_CHILD | WS_VISIBLE,
        160, 80, 47, 25, hwnd, NULL, hInstance, NULL);

    hPasswordText = CreateWindow("EDIT", "", WS_CHILD | WS_VISIBLE | WS_BORDER | ES_AUTOHSCROLL | ES_READONLY,
        10, 180, 275, 25, hwnd, (HMENU)ID_PASSWORD_TEXT, hInstance, NULL);

    hCopyBtn = CreateWindow("BUTTON", "Copy", WS_CHILD | WS_VISIBLE | BS_PUSHBUTTON | BS_OWNERDRAW,
        290, 180, 90, 25, hwnd, (HMENU)ID_COPY_BTN, hInstance, NULL);

    hFont = CreateFont(16, 0, 0, 0, FW_NORMAL, FALSE, FALSE, FALSE, DEFAULT_CHARSET,
        OUT_DEFAULT_PRECIS, CLIP_DEFAULT_PRECIS, DEFAULT_QUALITY,
        DEFAULT_PITCH | FF_DONTCARE, "Segoe UI");

    SendMessage(GetDlgItem(hwnd, ID_GENERATE_BTN), WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hLowercaseChk, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hUppercaseChk, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hDigitsChk, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hSymbolsChk, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hLengthEdit, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hPasswordText, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(hCopyBtn, WM_SETFONT, (WPARAM)hFont, TRUE);
    SendMessage(GetDlgItem(hwnd, -1), WM_SETFONT, (WPARAM)hFont, TRUE);

    SendMessage(hLowercaseChk, BM_SETCHECK, BST_CHECKED, 0);
    SendMessage(hUppercaseChk, BM_SETCHECK, BST_CHECKED, 0);
    SendMessage(hDigitsChk, BM_SETCHECK, BST_CHECKED, 0);

    ShowWindow(hCopyBtn, SW_SHOW);
    ShowWindow(hwnd, nCmdShow);
    UpdateWindow(hwnd);

    ZeroMemory(&nid, sizeof(nid));
    nid.cbSize = sizeof(nid);
    nid.hWnd = hwnd;
    nid.uID = 1;
    nid.uFlags = NIF_ICON | NIF_MESSAGE | NIF_TIP;
    nid.hIcon = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_ICON1));
    nid.uCallbackMessage = WM_USER + 1;
    strcpy(nid.szTip, "Password Generator");
    Shell_NotifyIcon(NIM_ADD, &nid);

    MSG msg;
    while (GetMessage(&msg, NULL, 0, 0)) {
        TranslateMessage(&msg);
        DispatchMessage(&msg);
    }

    return (int)msg.wParam;
}

LRESULT CALLBACK WndProc(HWND hwnd, UINT message, WPARAM wParam, LPARAM lParam) {
    switch (message) {
        case WM_COMMAND:
            switch (LOWORD(wParam)) {
                case ID_GENERATE_BTN:
                    GeneratePassword(hwnd);
                    break;
                case ID_COPY_BTN:
                    CopyPassword(hwnd);
                    break;
                case ID_FILE_EXIT:
                    Shell_NotifyIcon(NIM_DELETE, &nid);
                    PostQuitMessage(0);
                    break;
                case ID_TRAY_SHOW:
                    ShowWindow(hwnd, SW_RESTORE);
                    SetForegroundWindow(hwnd);
                    break;
                case ID_HELP_ABOUT:
                    ShowAboutDialog(hwnd);
                    break;
            }
            break;
        case WM_USER + 1:
            if (lParam == WM_RBUTTONUP) {
                HMENU hMenu = CreatePopupMenu();
                AppendMenu(hMenu, MF_STRING, ID_TRAY_SHOW, "Show");
                AppendMenu(hMenu, MF_STRING, ID_FILE_EXIT, "Exit");

                POINT pt;
                GetCursorPos(&pt);
                SetForegroundWindow(hwnd);
                TrackPopupMenu(hMenu, TPM_RIGHTBUTTON, pt.x, pt.y, 0, hwnd, NULL);
                DestroyMenu(hMenu);
                break;
            } else if (lParam == WM_LBUTTONDBLCLK) {
                ShowWindow(hwnd, SW_RESTORE);
                SetForegroundWindow(hwnd);
                break;
            }
            break;
        case WM_DRAWITEM: {
                LPDRAWITEMSTRUCT pDIS = (LPDRAWITEMSTRUCT)lParam;
                if (pDIS->CtlID == ID_GENERATE_BTN || pDIS->CtlID == ID_COPY_BTN) {
                    HBRUSH hBrush;
                    BOOL isMouseOver = (pDIS->CtlID == ID_GENERATE_BTN) ? isMouseOverGenerateBtn : isMouseOverCopyBtn;
                    bool btnTextColor = false;

                    if (pDIS->itemState & ODS_SELECTED) {
                        hBrush = CreateSolidBrush(RGB(200, 200, 200));
                        btnTextColor = true;
                    } else if (isMouseOver) {
                        hBrush = CreateSolidBrush(RGB(200, 200, 200));
                        btnTextColor = false;
                    } else {
                        hBrush = CreateSolidBrush(RGB(75, 75, 75));
                        btnTextColor = false;
                    }
                    FillRect(pDIS->hDC, &pDIS->rcItem, hBrush);
                    DeleteObject(hBrush);

                    SetBkMode(pDIS->hDC, TRANSPARENT);
                    if (btnTextColor) {
                        SetTextColor(pDIS->hDC, RGB(0, 0, 0));
                    } else {
                        SetTextColor(pDIS->hDC, RGB(255, 255, 255));
                    }

                    char text[256];
                    GetWindowText(pDIS->hwndItem, text, sizeof(text));

                    DrawText(pDIS->hDC, text, -1, &pDIS->rcItem, DT_CENTER | DT_VCENTER | DT_SINGLELINE);

                    return TRUE;
                }
            }
            break;
        case WM_CTLCOLORSTATIC:
        case WM_CTLCOLOREDIT: {
                HDC hdc = (HDC)wParam;
                SetBkColor(hdc, RGB(30, 30, 30));
                SetTextColor(hdc, RGB(255, 255, 255));
                return (INT_PTR)GetStockObject(NULL_BRUSH);
            }
            break;
        case WM_MOUSEMOVE: {
                POINT pt;
                pt.x = LOWORD(lParam);
                pt.y = HIWORD(lParam);

                RECT rcGenerateBtn, rcCopyBtn;
                GetWindowRect(hGenerateBtn, &rcGenerateBtn);
                GetWindowRect(hCopyBtn, &rcCopyBtn);
                ScreenToClient(hwnd, &pt);

                BOOL isMouseOverGenerate = PtInRect(&rcGenerateBtn, pt);
                BOOL isMouseOverCopy = PtInRect(&rcCopyBtn, pt);

                if (isMouseOverGenerate != isMouseOverGenerateBtn) {
                    isMouseOverGenerateBtn = isMouseOverGenerate;
                    InvalidateRect(hGenerateBtn, NULL, TRUE);
                }

                if (isMouseOverCopy != isMouseOverCopyBtn) {
                    isMouseOverCopyBtn = isMouseOverCopy;
                    InvalidateRect(hCopyBtn, NULL, TRUE);
                }
            }
            break;
        case WM_CLOSE:
            ShowWindow(hwnd, SW_HIDE);
            return 0;
        case WM_DESTROY:
            Shell_NotifyIcon(NIM_DELETE, &nid);
            PostQuitMessage(0);
            break;
        default:
            return DefWindowProc(hwnd, message, wParam, lParam);
    }

    return 0;
}

void GeneratePassword(HWND hwnd) {
    BOOL useLowercase = SendMessage(hLowercaseChk, BM_GETCHECK, 0, 0) == BST_CHECKED;
    BOOL useUppercase = SendMessage(hUppercaseChk, BM_GETCHECK, 0, 0) == BST_CHECKED;
    BOOL useDigits = SendMessage(hDigitsChk, BM_GETCHECK, 0, 0) == BST_CHECKED;
    BOOL useSymbols = SendMessage(hSymbolsChk, BM_GETCHECK, 0, 0) == BST_CHECKED;

    if (!useLowercase && !useUppercase && !useDigits && !useSymbols) {
        MessageBox(hwnd, "Âûáåðèòå õîòÿ áû îäèí òèï ñèìâîëîâ äëÿ ãåíåðàöèè ïàðîëÿ.", "Îøèáêà", MB_OK | MB_ICONERROR);
        return;
    }

    char lengthStr[4];
    GetWindowText(hLengthEdit, lengthStr, 4);
    int length = atoi(lengthStr);

    if (length < 4 || length > 32) {
        MessageBox(hwnd, "Äëèíà ïàðîëÿ äîëæíà áûòü îò 4 äî 32 ñèìâîëîâ.", "Îøèáêà", MB_OK | MB_ICONERROR);
        return;
    }

    char charset[128] = { 0 };
    int charsetLen = 0;

    if (useLowercase) {
        strcat(charset, LOWERCASE_CHARS);
        charsetLen += sizeof(LOWERCASE_CHARS) - 1;
    }

    if (useUppercase) {
        strcat(charset, UPPERCASE_CHARS);
        charsetLen += sizeof(UPPERCASE_CHARS) - 1;
    }

    if (useDigits) {
        strcat(charset, DIGIT_CHARS);
        charsetLen += sizeof(DIGIT_CHARS) - 1;
    }

    if (useSymbols) {
        strcat(charset, SYMBOL_CHARS);
        charsetLen += sizeof(SYMBOL_CHARS) - 1;
    }

    char password[33] = { 0 };
    for (int i = 0; i < length; i++) {
        int randomIndex = rand() % charsetLen;
        password[i] = charset[randomIndex];
    }

    SetWindowText(hPasswordText, password);
}

void CopyPassword(HWND hwnd) {
    char password[33];
    GetWindowText(hPasswordText, password, sizeof(password));

    if (OpenClipboard(hwnd)) {
        EmptyClipboard();

        HGLOBAL hMem = GlobalAlloc(GMEM_MOVEABLE, strlen(password) + 1);
        if (hMem != NULL) {
            char *memPtr = (char *)GlobalLock(hMem);
            if (memPtr != NULL)  {
                strcpy(memPtr, password);

                GlobalUnlock(hMem);

                SetClipboardData(CF_TEXT, hMem);
            }
        }

        CloseClipboard();
    }
}

void ShowAboutDialog(HWND hwnd) {
    char message[256];
    sprintf(message, "Password Generator %s\nA simple password generator.\nDeveloper - Taillogs.", VERSION);
    MessageBox(hwnd, message, "About Password Generator", MB_OK | MB_ICONINFORMATION);
}