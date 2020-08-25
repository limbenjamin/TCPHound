// TCPHound.cpp : Defines the entry point for the application.
//

#include "stdafx.h"
#include "TCPHound.h"
#include <iphlpapi.h>
#include <commctrl.h>
#include <vector>
#include <ctime>
#include <psapi.h>
#include <Commdlg.h>
#include "SHA256.h"
#include "getAS.h"
#include <fstream>

#define _CRTDBG_MAPALLOC
#define _CRTDBG_MAP_ALLOC

#define MAX_THREADS 1
#define BUF_SIZE 255


#pragma comment(lib, "Ws2_32.lib")
#pragma comment(lib, "comctl32.lib")
#pragma comment(linker,"\"/manifestdependency:type='win32' name='Microsoft.Windows.Common-Controls' version='6.0.0.0' processorArchitecture='*' publicKeyToken='6595b64144ccf1df' language='*'\"")

#include "libcurl/x64/curl.h"
#pragma comment(lib, "libcurl/x64/libcurl_a.lib")
#pragma comment(lib, "libcurl/x86/libcurl_a.lib")

#define MAX_LOADSTRING 100

// Data structure for TCP table info
DWORD(WINAPI *pGetExtendedTcpTable)(
	PVOID pTcpTable,
	PDWORD pdwSize,
	BOOL bOrder,
	ULONG ulAf,
	TCP_TABLE_CLASS TableClass,
	ULONG Reserved
	);

// Custom Data structure for table
struct Tuple {
	int id;
	char connOpen[64];
	tm connOpenTime;
	char connClose[64];
	tm connCloseTime;
	int connDuration; // In seconds
	char localAddr[128]; 
	unsigned short localPort; 
	char remoteAddr[128]; 
	unsigned short remotePort;
	short pid; 
	char imageName[128];
	char fullPath[384];
	char asInfo[2048];
	char sha256[65];
	bool found; // Has this entry been found in the latest scan. If not, it means that the connection was just closed.
	bool displayed; // Is this entry already displayed in windowlist
	bool stateOpen; // Has this entry been changed from SYN_SENT to open.
};

// Global Variables:
HINSTANCE hInst;                                // current instance
WCHAR szTitle[MAX_LOADSTRING];                  // The title bar text
WCHAR szWindowClass[MAX_LOADSTRING];            // the main window class name
HANDLE hThread;									// Handler for threads for polling
DWORD dwThreadId;
HWND parentWindow;								// Handler for Windows
HWND listWindow;
HMENU menu;
HMENU popup;
MIB_TCPTABLE_OWNER_PID *pTCPInfo;				// TCP Table
MIB_TCPROW_OWNER_PID *row;
std::vector<Tuple> dbTable;							// Main Table with all attributes
bool enabled;									// Is polling enabled
int currentID;									// Current connection id given out
bool showClipBoardmessage;						// hash copied to clipboard message will only be shown once per run.

// Function Prototype

int getNetConnectionInfo();
DWORD WINAPI threadPollNetConnection(LPVOID lpParam);
char* updateAsInfo(wchar_t* ip);
char* updateHashInfo(wchar_t* ip);
void toClipboard(const std::string &s);
int ClearDisplay(int type);

// Forward declarations of functions included in this code module:
ATOM                MyRegisterClass(HINSTANCE hInstance);
BOOL                InitInstance(HINSTANCE, int);
LRESULT CALLBACK    WndProc(HWND, UINT, WPARAM, LPARAM);
INT_PTR CALLBACK    About(HWND, UINT, WPARAM, LPARAM);


int APIENTRY wWinMain(_In_ HINSTANCE hInstance,
                     _In_opt_ HINSTANCE hPrevInstance,
                     _In_ LPWSTR    lpCmdLine,
                     _In_ int       nCmdShow)
{
    UNREFERENCED_PARAMETER(hPrevInstance);
    UNREFERENCED_PARAMETER(lpCmdLine);

    // TODO: Place code here.

    // Initialize global strings
    LoadStringW(hInstance, IDS_APP_TITLE, szTitle, MAX_LOADSTRING);
    LoadStringW(hInstance, IDC_TCPHOUND, szWindowClass, MAX_LOADSTRING);
    MyRegisterClass(hInstance);

    // Perform application initialization:
    if (!InitInstance (hInstance, nCmdShow))
    {
        return FALSE;
    }

    HACCEL hAccelTable = LoadAccelerators(hInstance, MAKEINTRESOURCE(IDC_TCPHOUND));

    MSG msg;

    // Main message loop:
    while (GetMessage(&msg, nullptr, 0, 0))
    {
        if (!TranslateAccelerator(msg.hwnd, hAccelTable, &msg))
        {
            TranslateMessage(&msg);
            DispatchMessage(&msg);
        }

    }

    return (int) msg.wParam;
}



//
//  FUNCTION: MyRegisterClass()
//
//  PURPOSE: Registers the window class.
//
ATOM MyRegisterClass(HINSTANCE hInstance)
{
    WNDCLASSEXW wcex;

    wcex.cbSize = sizeof(WNDCLASSEX);

    wcex.style          = CS_HREDRAW | CS_VREDRAW;
    wcex.lpfnWndProc    = WndProc;
    wcex.cbClsExtra     = 0;
    wcex.cbWndExtra     = 0;
    wcex.hInstance      = hInstance;
    wcex.hIcon          = LoadIcon(hInstance, MAKEINTRESOURCE(IDI_TCPHOUND));
    wcex.hCursor        = LoadCursor(nullptr, IDC_ARROW);
    wcex.hbrBackground  = (HBRUSH)(COLOR_WINDOW+1);
    wcex.lpszMenuName   = MAKEINTRESOURCEW(IDC_TCPHOUND);
    wcex.lpszClassName  = szWindowClass;
    wcex.hIconSm        = LoadIcon(wcex.hInstance, MAKEINTRESOURCE(IDI_SMALL));

    return RegisterClassExW(&wcex);
}

//
//   FUNCTION: InitInstance(HINSTANCE, int)
//
//   PURPOSE: Saves instance handle and creates main window
//
//   COMMENTS:
//
//        In this function, we save the instance handle in a global variable and
//        create and display the main program window.
//
BOOL InitInstance(HINSTANCE hInstance, int nCmdShow)
{
   hInst = hInstance; // Store instance handle in our global variable

   parentWindow = CreateWindowEx(0, szWindowClass, szTitle, WS_OVERLAPPEDWINDOW,
      CW_USEDEFAULT, 0, CW_USEDEFAULT, 0, nullptr, nullptr, hInstance, nullptr);

   if (!parentWindow)
   {
      return FALSE;
   }

   ShowWindow(parentWindow, nCmdShow);
   UpdateWindow(parentWindow);

   RECT rcClient;                       // The parent window's client area.
   GetClientRect(parentWindow, &rcClient);

   INITCOMMONCONTROLSEX icex;           // Structure for control initialization.
   icex.dwICC = ICC_LISTVIEW_CLASSES;
   InitCommonControlsEx(&icex);

   listWindow = CreateWindowEx(0, WC_LISTVIEW, L"", WS_CHILD | LVS_REPORT | LVS_SINGLESEL, 0, 0, rcClient.right - rcClient.left, rcClient.bottom - rcClient.top, parentWindow, NULL, hInst, NULL);

   SendMessage(listWindow, LVM_SETEXTENDEDLISTVIEWSTYLE, LVS_EX_DOUBLEBUFFER | LVS_EX_FULLROWSELECT | LVS_EX_LABELTIP , LVS_EX_FULLROWSELECT | LVS_EX_LABELTIP); // extended styles (must be sent as a message!)

   LVCOLUMN LvCol;
   LvCol.mask = LVCF_TEXT | LVCF_WIDTH | LVCF_SUBITEM;    // Type of mask
   LvCol.cx = 0x28;										// width between each coloum
   LvCol.cx = 0x32;
   LvCol.pszText = L"ID";                             // Next coloum
   SendMessage(listWindow, LVM_INSERTCOLUMN, 0, (LPARAM)&LvCol);
   LvCol.cx = 0x96;										 // width of column
   LvCol.pszText = L"Connection Opened";                            // First Header Text                                     
   SendMessage(listWindow, LVM_INSERTCOLUMN, 1, (LPARAM)&LvCol); // Insert/Show the coloum
   LvCol.cx = 0x32;
   LvCol.pszText = L"PID";                             // Next coloum
   SendMessage(listWindow, LVM_INSERTCOLUMN, 2, (LPARAM)&LvCol); 
   LvCol.cx = 0x64;
   LvCol.pszText = L"Local Address"; 
   SendMessage(listWindow, LVM_INSERTCOLUMN, 3, (LPARAM)&LvCol); 
   LvCol.cx = 0x48;
   LvCol.pszText = L"Local Port"; 
   SendMessage(listWindow, LVM_INSERTCOLUMN, 4, (LPARAM)&LvCol);
   LvCol.cx = 0x64;
   LvCol.pszText = L"Remote Address"; 
   SendMessage(listWindow, LVM_INSERTCOLUMN, 5, (LPARAM)&LvCol);
   LvCol.cx = 0x64;
   LvCol.pszText = L"Remote Port";
   SendMessage(listWindow, LVM_INSERTCOLUMN, 6, (LPARAM)&LvCol);
   LvCol.cx = 0x96;
   LvCol.pszText = L"Connected Closed";
   SendMessage(listWindow, LVM_INSERTCOLUMN, 7, (LPARAM)&LvCol);
   LvCol.cx = 0x64;
   LvCol.pszText = L"Duration (secs)";
   SendMessage(listWindow, LVM_INSERTCOLUMN, 8, (LPARAM)&LvCol);
   LvCol.cx = 0x64;
   LvCol.pszText = L"Image Name";
   SendMessage(listWindow, LVM_INSERTCOLUMN, 9, (LPARAM)&LvCol);
   LvCol.cx = 0x64;
   LvCol.pszText = L"AS Info";
   SendMessage(listWindow, LVM_INSERTCOLUMN, 10, (LPARAM)&LvCol);
   LvCol.cx = 0x128;
   LvCol.pszText = L"Full Path";
   SendMessage(listWindow, LVM_INSERTCOLUMN, 11, (LPARAM)&LvCol);
   LvCol.cx = 0x64;
   LvCol.pszText = L"SHA256 Hash";
   SendMessage(listWindow, LVM_INSERTCOLUMN, 12, (LPARAM)&LvCol);

   ShowWindow(listWindow, SW_SHOW);
   UpdateWindow(listWindow);

   hThread = CreateThread(
	   NULL,                   // default security attributes
	   0,                      // use default stack size  
	   threadPollNetConnection,       // thread function name
	   NULL,          // argument to thread function 
	   0,                      // use default creation flags 
	   &dwThreadId);   // returns the thread identifier

   currentID = 0; // set connection ID to 0

   enabled = true; // start the application in enabled state.
   menu = GetMenu(parentWindow);
   EnableMenuItem(menu, IDM_ENABLE, MF_GRAYED);
   curl_global_init(CURL_GLOBAL_DEFAULT);
   showClipBoardmessage = false;

   if (hThread == NULL)
   {
	   ExitProcess(3);
   }

   return TRUE;
}

//
//  FUNCTION: WndProc(HWND, UINT, WPARAM, LPARAM)
//
//  PURPOSE:  Processes messages for the main window.
//
//  WM_COMMAND  - process the application menu
//  WM_PAINT    - Paint the main window
//  WM_DESTROY  - post a quit message and return
//
//
LRESULT CALLBACK WndProc(HWND parentWindow, UINT message, WPARAM wParam, LPARAM lParam)
{
    switch (message)
    {
    case WM_COMMAND:
        {
            int wmId = LOWORD(wParam);
            // Parse the menu selections:
            switch (wmId)
            {
            case IDM_ABOUT:
                DialogBox(hInst, MAKEINTRESOURCE(IDD_ABOUTBOX), parentWindow, About);
                break;
			case IDM_DISABLE:
				enabled = FALSE;
				EnableMenuItem(menu, IDM_DISABLE, MF_GRAYED);
				EnableMenuItem(menu, IDM_ENABLE, MF_ENABLED);
				break;
			case IDM_ENABLE:
				enabled = TRUE;
				EnableMenuItem(menu, IDM_ENABLE, MF_GRAYED);
				EnableMenuItem(menu, IDM_DISABLE, MF_ENABLED);
				break;
			case ID_DISPLAY_CLEARDISPLAY:
				ClearDisplay(0);
				break;
			case ID_DISPLAY_CLEARCLOSEDCONNECTIONS:
				ClearDisplay(1);
				break;
			case IDM_EXPORT:
				wchar_t filename[MAX_PATH];
				OPENFILENAME ofn;
				ZeroMemory(&filename, sizeof(filename));
				ZeroMemory(&ofn, sizeof(ofn));
				ofn.lStructSize = sizeof(ofn);
				ofn.hwndOwner = parentWindow;  // If you have a window to center over, put its HANDLE here
				ofn.lpstrFilter = L"Comma Separated Values (.csv)\0*.csv\0";
				ofn.lpstrFile = filename;
				ofn.lpstrDefExt = L"csv";
				ofn.nMaxFile = MAX_PATH;
				ofn.lpstrTitle = L"Select a File";
				ofn.Flags = OFN_DONTADDTORECENT | OFN_FILEMUSTEXIST;
				if (GetSaveFileNameW(&ofn))
				{
					std::ofstream outfile;
					outfile.open(filename);
					outfile << "Id" << ",";
					outfile << "Connection Opened" << ",";
					outfile << "PID" << ",";
					outfile << "Local Address" << ",";
					outfile << "Local Port" << ",";
					outfile << "Remote Address" << ",";
					outfile << "Remote Port" << ",";
					outfile << "Connection Closed" << ",";
					outfile << "Duration (secs)" << ",";
					outfile << "Image Name" << ",";
					outfile << "AS Info" << ",";
					outfile << "Full Path" << ",";
					outfile << "SHA256 Hash";
					outfile << std::endl;
					for (auto it = std::begin(dbTable); it != std::end(dbTable); ++it) {
						outfile << it->id << ",";
						outfile << it->connOpen << ",";
						outfile << it->pid << ",";
						outfile << it->localAddr << ",";
						outfile << it->localPort << ",";
						outfile << it->remoteAddr << ",";
						outfile << it->remotePort << ",";
						outfile << it->connClose << ",";
						outfile << it->connDuration << ",";
						outfile << it->imageName << ",";

						//AS info could have comma, hence need to quote it
						outfile << "\"" << it->asInfo << "\""  << ",";
						outfile << it->fullPath << ",";
						outfile << it->sha256;
						outfile << std::endl;
					}
					outfile.close();
				}

				break;
            case IDM_EXIT:
				_CrtDumpMemoryLeaks();
                DestroyWindow(parentWindow);
                break;
            default:
                return DefWindowProc(parentWindow, message, wParam, lParam);
            }
        }
        break;
    case WM_PAINT:
        {
            PAINTSTRUCT ps;
            HDC hdc = BeginPaint(parentWindow, &ps);
			RECT rcClient;                       // The parent window's client area.
			GetClientRect(parentWindow, &rcClient);
			SetWindowPos(listWindow, HWND_TOP, 0, 0, rcClient.right - rcClient.left, rcClient.bottom - rcClient.top, NULL);
            // TODO: Add any drawing code that uses hdc here...
            EndPaint(parentWindow, &ps);
        }
        break;
    case WM_DESTROY:
		curl_global_cleanup();
        PostQuitMessage(0);
        break;
	case WM_NOTIFY:
		// When right button clicked on mouse
		if ((((LPNMHDR)lParam)->hwndFrom) == listWindow)
		{
			switch (((LPNMHDR)lParam)->code)
			{
				case NM_RCLICK:
				{
					int itemSelected = SendMessage(listWindow, LVM_GETNEXTITEM, -1, LVNI_SELECTED);
					if (itemSelected != -1) //if no item selected, dont display popup
					{
						POINT cursor; // Getting the cursor position
						GetCursorPos(&cursor);
						// Creating the popup menu list
						popup = CreatePopupMenu();
						InsertMenu(popup, 0, MF_BYCOMMAND | MF_STRING | MF_ENABLED, IDM_GETAS, TEXT("Get As Info"));
						InsertMenu(popup, 0, MF_BYCOMMAND | MF_STRING | MF_ENABLED, IDM_GETSHA256HASH, TEXT("Get SHA256 Hash"));
						UINT Selection = TrackPopupMenu(popup, TPM_LEFTALIGN | TPM_RIGHTBUTTON | TPM_RETURNCMD, cursor.x, cursor.y, 0, listWindow, NULL);
						if (Selection == 113) { // Get AS Button clicked
							LVITEM LvItem;
							wchar_t buffer[256];

							// Get ip address
							memset(&LvItem, 0, sizeof(LvItem));
							LvItem.mask = LVIF_TEXT;
							LvItem.iSubItem = 5;
							LvItem.pszText = buffer;
							LvItem.cchTextMax = 256;
							LvItem.iItem = itemSelected;
							SendMessage(listWindow, LVM_GETITEMTEXT, itemSelected, (LPARAM)&LvItem);
							char *as = updateAsInfo(buffer);

							// Display As info
							memset(&LvItem, 0, sizeof(LvItem));
							LvItem.mask = LVIF_TEXT;
							LvItem.iSubItem = 10;
							wsprintfW(buffer, L"%S", as);
							LvItem.pszText = buffer;
							LvItem.cchTextMax = 256;
							LvItem.iItem = itemSelected;
							
							SendMessage(listWindow, LVM_SETITEM, itemSelected, (LPARAM)&LvItem);
						}
						if (Selection == 129) { // Get SHA256 Hash Button clicked
							LVITEM LvItem;
							wchar_t buffer[256];

							// Get full path
							memset(&LvItem, 0, sizeof(LvItem));
							LvItem.mask = LVIF_TEXT;
							LvItem.iSubItem = 11;
							LvItem.pszText = buffer;
							LvItem.cchTextMax = 256;
							LvItem.iItem = itemSelected;
							SendMessage(listWindow, LVM_GETITEMTEXT, itemSelected, (LPARAM)&LvItem);
							char *hash = updateHashInfo(buffer);

							// Display hash info
							memset(&LvItem, 0, sizeof(LvItem));
							LvItem.mask = LVIF_TEXT;
							LvItem.iSubItem = 12;
							wsprintfW(buffer, L"%S", hash);
							LvItem.pszText = buffer;
							LvItem.cchTextMax = 256;
							LvItem.iItem = itemSelected;

							SendMessage(listWindow, LVM_SETITEM, itemSelected, (LPARAM)&LvItem);
							toClipboard(hash);
							if (showClipBoardmessage == false) {
								MessageBox(NULL, L"Hash will always be automatically copied to clipboard", L"Get SHA256 Hash", MB_ICONINFORMATION | MB_OK);
								showClipBoardmessage = true;
							}
						}
					}
				}
				break;
			}
			break;
		}
		break;
    default:
        return DefWindowProc(parentWindow, message, wParam, lParam);
    }
    return 0;
}

// Message handler for about box.
INT_PTR CALLBACK About(HWND hDlg, UINT message, WPARAM wParam, LPARAM lParam)
{
    UNREFERENCED_PARAMETER(lParam);
    switch (message)
    {
    case WM_INITDIALOG:
        return (INT_PTR)TRUE;

    case WM_COMMAND:
        if (LOWORD(wParam) == IDOK || LOWORD(wParam) == IDCANCEL)
        {
            EndDialog(hDlg, LOWORD(wParam));
            return (INT_PTR)TRUE;
        }
        break;
    }
    return (INT_PTR)FALSE;
}

int getNetConnectionInfo() {
	DWORD size;
	DWORD dwResult;

	HMODULE hLib = LoadLibrary(L"iphlpapi.dll");

	pGetExtendedTcpTable = (DWORD(WINAPI *)(PVOID, PDWORD, BOOL, ULONG, TCP_TABLE_CLASS, ULONG))
		GetProcAddress(hLib, "GetExtendedTcpTable");

	if (!pGetExtendedTcpTable)
	{
		printf("Could not load iphlpapi.dll. This application is for Windows XP SP2 and up.\n");
		return 1;
	}

	dwResult = pGetExtendedTcpTable(NULL, &size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);
	pTCPInfo = (MIB_TCPTABLE_OWNER_PID*)malloc(size);
	dwResult = pGetExtendedTcpTable(pTCPInfo, &size, false, AF_INET, TCP_TABLE_OWNER_PID_ALL, 0);

	if (dwResult != NO_ERROR)
	{
		printf("Couldn't get our IP table");
		return 2;
	}


	return 0;
}

DWORD WINAPI threadPollNetConnection(LPVOID lpParam)
{
	HANDLE hStdout;
	wchar_t buffer[256];
	struct in_addr IpAddr;

	hStdout = GetStdHandle(STD_OUTPUT_HANDLE);
	if (hStdout == INVALID_HANDLE_VALUE)
		return 1;

	while (true) {

		if (enabled == FALSE) {
			Sleep(5000);
			continue;
		}

		int result = getNetConnectionInfo();
		time_t currentTime = std::time(NULL);

		// reset update flag all to false
		for (auto it = std::begin(dbTable); it != std::end(dbTable); ++it) {
			it->found = FALSE;
		}

		for (int i = 0; i < (int) pTCPInfo->dwNumEntries; i++)
		{
			row = &pTCPInfo->table[i];
			if (row->dwState == MIB_TCP_STATE_SYN_SENT || row->dwState == MIB_TCP_STATE_ESTAB || row->dwState == MIB_TCP_STATE_FIN_WAIT1 || row->dwState == MIB_TCP_STATE_FIN_WAIT2 || row->dwState == MIB_TCP_STATE_CLOSING) {
				Tuple tuple;
				tuple.pid = row->dwOwningPid;
				IpAddr.S_un.S_addr = (u_long)row->dwLocalAddr;
				strcpy_s(tuple.localAddr, sizeof(tuple.localAddr), inet_ntoa(IpAddr));
				tuple.localPort = ntohs(row->dwLocalPort);
				IpAddr.S_un.S_addr = (u_long)row->dwRemoteAddr;
				strcpy_s(tuple.remoteAddr, sizeof(tuple.remoteAddr), inet_ntoa(IpAddr));
				tuple.remotePort = ntohs(row->dwRemotePort);
				strftime(tuple.connOpen,80, "%d-%m-%Y %I:%M:%S", localtime(&currentTime));
				tuple.connOpenTime = *localtime(&currentTime);
				strcpy_s(tuple.connClose, sizeof(tuple.connClose), "OPEN");
				if (row->dwState == MIB_TCP_STATE_SYN_SENT) {
					strcpy_s(tuple.connClose, sizeof(tuple.connClose), "SYN_SENT");
				}
				tuple.connDuration = 0;
				tuple.sha256[0] = '\0';
				HANDLE Handle = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, tuple.pid);
				if (Handle)
				{
					TCHAR Buffer[MAX_PATH];
					if (GetModuleFileNameEx(Handle, 0, Buffer, MAX_PATH))
					{
						wcstombs(tuple.fullPath, Buffer, sizeof(tuple.fullPath));
					}
					if (GetModuleBaseName(Handle, 0, Buffer, MAX_PATH))
					{
						wcstombs(tuple.imageName, Buffer, sizeof(tuple.imageName));
					}
					CloseHandle(Handle);
					Handle = NULL;
				}else {
					tuple.fullPath[0] = '\0';
					tuple.imageName[0] = '\0';
				}

				//   insertion of new items into table   //

				// if vector empty, insert first entry automatically

				if (dbTable.empty()) {
					tuple.id = currentID;
					currentID++;
					tuple.asInfo[0] = '\0';
					tuple.found = TRUE;		// TRUE, was found in current scan
					tuple.displayed = FALSE; // New tuple, not displayed yet
					dbTable.emplace_back(tuple);
					continue;
				}

				//  if tuple found, set to true, else new entry, so insert

				for (auto it = std::begin(dbTable); it != std::end(dbTable); ++it) {
					if (it->pid == tuple.pid && it->localPort == tuple.localPort && it->remotePort == tuple.remotePort) {
						if (strcmp(it->remoteAddr, tuple.remoteAddr) == 0 && strcmp(it->localAddr, tuple.localAddr) == 0) {
							it->found = TRUE;
							// if change in connstate
							if (strcmp(it->connClose, tuple.connClose) != 0) {
								it->stateOpen = TRUE;
							}
							break;
						}
					}
					else if ((it != dbTable.end()) && (next(it) == dbTable.end())){
						tuple.id = currentID;
						currentID++;
						tuple.asInfo[0] = '\0';
						tuple.found = TRUE;		// TRUE, was found in current scan
						tuple.displayed = FALSE; // New tuple, not displayed yet
						dbTable.emplace_back(tuple);
						break;
					}
				}
			}
		}

		delete(pTCPInfo);

		//clear blank slate
		//ListView_DeleteAllItems(listWindow);

		for (auto it = std::begin(dbTable); it != std::end(dbTable); ++it) {

			if (it->displayed == FALSE) {

				// print to table

				LVITEM LvItem;
				LvItem.mask = LVIF_TEXT;   // Text Style
				LvItem.cchTextMax = 256; // Max size of test
				LvItem.iItem = 0;          // choose item
				LvItem.iSubItem = 0;       // Put in first colvector 
				wsprintfW(buffer, L"%d", it->id);
				LvItem.pszText = buffer;
				SendMessage(listWindow, LVM_INSERTITEM, 0, (LPARAM)&LvItem); // Send to the Listview
				LvItem.iSubItem = 1;
				wsprintfW(buffer, L"%S", it->connOpen);
				LvItem.pszText = buffer;
				SendMessage(listWindow, LVM_SETITEM, 0, (LPARAM)&LvItem); // Send to the Listview
				LvItem.iSubItem = 2;
				wsprintfW(buffer, L"%d", it->pid);
				LvItem.pszText = buffer;
				SendMessage(listWindow, LVM_SETITEM, 0, (LPARAM)&LvItem); // Send to the Listview
				LvItem.iSubItem = 3;
				wsprintfW(buffer, L"%S", it->localAddr);
				LvItem.pszText = buffer; // Text to display (can be from a char variable) (Items)
				SendMessage(listWindow, LVM_SETITEM, 0, (LPARAM)&LvItem); // Send to the Listview
				LvItem.iSubItem = 4;
				wsprintfW(buffer, L"%d", it->localPort);
				LvItem.pszText = buffer; // Text to display (can be from a char variable) (Items)
				SendMessage(listWindow, LVM_SETITEM, 0, (LPARAM)&LvItem); // Send to the Listview
				LvItem.iSubItem = 5;
				wsprintfW(buffer, L"%S", it->remoteAddr);
				LvItem.pszText = buffer; // Text to display (can be from a char variable) (Items)
				SendMessage(listWindow, LVM_SETITEM, 0, (LPARAM)&LvItem);
				LvItem.iSubItem = 6;
				wsprintfW(buffer, L"%d", it->remotePort);
				LvItem.pszText = buffer; // Text to display (can be from a char variable) (Items)
				SendMessage(listWindow, LVM_SETITEM, 0, (LPARAM)&LvItem);
				LvItem.iSubItem = 7;
				wsprintfW(buffer, L"%S", it->connClose);
				LvItem.pszText = buffer; // Text to display (can be from a char variable) (Items)
				SendMessage(listWindow, LVM_SETITEM, 0, (LPARAM)&LvItem);
				LvItem.iSubItem = 8;
				wsprintfW(buffer, L"%d", it->connDuration);
				LvItem.pszText = buffer; // Text to display (can be from a char variable) (Items)
				SendMessage(listWindow, LVM_SETITEM, 0, (LPARAM)&LvItem);
				LvItem.iSubItem = 9;
				wsprintfW(buffer, L"%S", it->imageName);
				LvItem.pszText = buffer; // Text to display (can be from a char variable) (Items)
				SendMessage(listWindow, LVM_SETITEM, 0, (LPARAM)&LvItem);
				LvItem.iSubItem = 10;
				wsprintfW(buffer, L"%S", it->asInfo);
				LvItem.pszText = buffer; // Text to display (can be from a char variable) (Items)
				SendMessage(listWindow, LVM_SETITEM, 0, (LPARAM)&LvItem);
				LvItem.iSubItem = 11;
				wsprintfW(buffer, L"%S", it->fullPath);
				LvItem.pszText = buffer; // Text to display (can be from a char variable) (Items)
				SendMessage(listWindow, LVM_SETITEM, 0, (LPARAM)&LvItem);
				LvItem.iSubItem = 12;
				wsprintfW(buffer, L"%S", it->sha256);
				LvItem.pszText = buffer; // Text to display (can be from a char variable) (Items)
				SendMessage(listWindow, LVM_SETITEM, 0, (LPARAM)&LvItem);

				it->displayed = TRUE;

			}
			// Connection was just closed. Update dbtable and view
			else if (it->found == FALSE && strcmp(it->connClose, "OPEN") == 0) {
				int index;
				strftime(it->connClose, 64, "%d-%m-%Y %I:%M:%S", localtime(&currentTime));
				it->connCloseTime = *localtime(&currentTime);
				double diff = difftime(mktime(&it->connCloseTime), mktime(&it->connOpenTime));
				it->connDuration = (int)diff;
				int item;
				
				
				int iNumItems = ListView_GetItemCount(listWindow);
				for (int iIndex = 0; iIndex < iNumItems; ++iIndex)
				{
					LVITEM LvItem;
					ListView_GetItemPosition(listWindow, iIndex, &LvItem);
				}


				index = ListView_GetItemCount(listWindow) - 1 - it->id; // actually should take sizeof(dbtable) - id instead of getitemcount, but buggy, -1 due to 0 index
				wsprintfW(buffer, L"%S", it->connClose);
				LVITEM LvItem;
				LvItem.mask = LVIF_TEXT;
				LvItem.cchTextMax = 256;
				LvItem.pszText = buffer;
				ListView_SetItemText(listWindow, index, 7, buffer, 256);
				wsprintfW(buffer, L"%d", it->connDuration);
				LvItem.pszText = buffer;
				ListView_SetItemText(listWindow, index, 8, buffer, 256);
				UpdateWindow(listWindow);

			}

			// Connection changed state from SYN_SENT to OPEN
			if (it->stateOpen == TRUE && strcmp(it->connClose, "SYN_SENT") == 0) {
				it->stateOpen = FALSE;
				strcpy(it->connClose, "OPEN");
				int index;
				index = ListView_GetItemCount(listWindow) - 1 - it->id;
				wsprintfW(buffer, L"%S", "OPEN");
				LVITEM LvItem;
				LvItem.mask = LVIF_TEXT;
				LvItem.cchTextMax = 256;
				LvItem.pszText = buffer;
				ListView_SetItemText(listWindow, index, 7, buffer, 256);
				UpdateWindow(listWindow);
			}

		}
		ShowWindow(listWindow, SW_SHOW);
		UpdateWindow(listWindow);
		
		// Pause a moment
		Sleep(10);
		
	}

	return 0;
}

char* updateAsInfo(wchar_t* ip)
{
	std::wstring wIP(ip);
	std::string ipStr(wIP.begin(), wIP.end());
	char *ipChar = new char[ipStr.size() + 1];
	std::strcpy(ipChar, ipStr.c_str());

	char *outputBuffer = new char[1024];

	GetASInfo(ipChar, outputBuffer);


	// Update AS info into DB
	for (auto it = std::begin(dbTable); it != std::end(dbTable); ++it) {
		if (strcmp(it->remoteAddr, ipChar) == 0) {
			strcpy_s(it->asInfo, sizeof(it->asInfo), outputBuffer);
		}
	}

	return outputBuffer;
}

char* updateHashInfo(wchar_t* fullpath)
{
	std::wstring wFP(fullpath);
	if (fullpath[0] == '\0') {
		return "Unable to get Hash";
	}
	std::string fullpathStr(wFP.begin(), wFP.end());
	char *fullpathChar = new char[fullpathStr.size() + 1];
	std::strcpy(fullpathChar, fullpathStr.c_str());

	char *outputBuffer = new char[65];

	HashFileSHA256(fullpathChar, outputBuffer);

	// Update hash info into DB
	for (auto it = std::begin(dbTable); it != std::end(dbTable); ++it) {
		if (strcmp(it->fullPath, fullpathChar) == 0) {
			strcpy_s(it->sha256, sizeof(it->sha256), outputBuffer);
		}
	}
	return outputBuffer;
}



void toClipboard(const std::string &s) {
	OpenClipboard(0);
	EmptyClipboard();
	HGLOBAL hg = GlobalAlloc(GMEM_MOVEABLE, s.size()+1);
	if (!hg) {
		CloseClipboard();
		return;
	}
	memcpy(GlobalLock(hg), s.c_str(), s.size());
	GlobalUnlock(hg);
	SetClipboardData(CF_TEXT, hg);
	CloseClipboard();
	GlobalFree(hg);
}

// if type = 0, clear all
// if type = 1, clear closed connections
int ClearDisplay(int type) {
	enabled = false;
	Sleep(10);
	if (type == 0)
	{
		if (!dbTable.empty()) {
			dbTable.clear();
		}
		ListView_DeleteAllItems(listWindow);
		currentID = 0;
	}
	else {
		// type = 1, clear closed connections 
		// clear closed connection from dbTable
		std::vector<Tuple>::iterator it = dbTable.begin();
		for (; it != dbTable.end();) {
			if ((strcmp(it->connClose, "OPEN") != 0) && (strcmp(it->connClose, "SYN_SENT") != 0)) {
				it = dbTable.erase(it);
			}
			else {
				++it;
			}
		}

		// remove all entries in listview and repopulate from dbTable

		ListView_DeleteAllItems(listWindow);
		wchar_t buffer[256];
		for (auto it = std::begin(dbTable); it != std::end(dbTable); ++it) {

			LVITEM LvItem;
			LvItem.mask = LVIF_TEXT;   // Text Style
			LvItem.cchTextMax = 256; // Max size of test
			LvItem.iItem = 0;          // choose item
			LvItem.iSubItem = 0;       // Put in first colvector 
			wsprintfW(buffer, L"%d", it->id);
			LvItem.pszText = buffer;
			SendMessage(listWindow, LVM_INSERTITEM, 0, (LPARAM)&LvItem); // Send to the Listview
			LvItem.iSubItem = 1;
			wsprintfW(buffer, L"%S", it->connOpen);
			LvItem.pszText = buffer;
			SendMessage(listWindow, LVM_SETITEM, 0, (LPARAM)&LvItem); // Send to the Listview
			LvItem.iSubItem = 2;
			wsprintfW(buffer, L"%d", it->pid);
			LvItem.pszText = buffer;
			SendMessage(listWindow, LVM_SETITEM, 0, (LPARAM)&LvItem); // Send to the Listview
			LvItem.iSubItem = 3;
			wsprintfW(buffer, L"%S", it->localAddr);
			LvItem.pszText = buffer; // Text to display (can be from a char variable) (Items)
			SendMessage(listWindow, LVM_SETITEM, 0, (LPARAM)&LvItem); // Send to the Listview
			LvItem.iSubItem = 4;
			wsprintfW(buffer, L"%d", it->localPort);
			LvItem.pszText = buffer; // Text to display (can be from a char variable) (Items)
			SendMessage(listWindow, LVM_SETITEM, 0, (LPARAM)&LvItem); // Send to the Listview
			LvItem.iSubItem = 5;
			wsprintfW(buffer, L"%S", it->remoteAddr);
			LvItem.pszText = buffer; // Text to display (can be from a char variable) (Items)
			SendMessage(listWindow, LVM_SETITEM, 0, (LPARAM)&LvItem);
			LvItem.iSubItem = 6;
			wsprintfW(buffer, L"%d", it->remotePort);
			LvItem.pszText = buffer; // Text to display (can be from a char variable) (Items)
			SendMessage(listWindow, LVM_SETITEM, 0, (LPARAM)&LvItem);
			LvItem.iSubItem = 7;
			wsprintfW(buffer, L"%S", it->connClose);
			LvItem.pszText = buffer; // Text to display (can be from a char variable) (Items)
			SendMessage(listWindow, LVM_SETITEM, 0, (LPARAM)&LvItem);
			LvItem.iSubItem = 8;
			wsprintfW(buffer, L"%d", it->connDuration);
			LvItem.pszText = buffer; // Text to display (can be from a char variable) (Items)
			SendMessage(listWindow, LVM_SETITEM, 0, (LPARAM)&LvItem);
			LvItem.iSubItem = 9;
			wsprintfW(buffer, L"%S", it->imageName);
			LvItem.pszText = buffer; // Text to display (can be from a char variable) (Items)
			SendMessage(listWindow, LVM_SETITEM, 0, (LPARAM)&LvItem);
			LvItem.iSubItem = 10;
			wsprintfW(buffer, L"%S", it->asInfo);
			LvItem.pszText = buffer; // Text to display (can be from a char variable) (Items)
			SendMessage(listWindow, LVM_SETITEM, 0, (LPARAM)&LvItem);
			LvItem.iSubItem = 11;
			wsprintfW(buffer, L"%S", it->fullPath);
			LvItem.pszText = buffer; // Text to display (can be from a char variable) (Items)
			SendMessage(listWindow, LVM_SETITEM, 0, (LPARAM)&LvItem);
			LvItem.iSubItem = 12;
			wsprintfW(buffer, L"%S", it->sha256);
			LvItem.pszText = buffer; // Text to display (can be from a char variable) (Items)
			SendMessage(listWindow, LVM_SETITEM, 0, (LPARAM)&LvItem);

		}

	}
	enabled = true;
	Sleep(10);
	return 0;
}