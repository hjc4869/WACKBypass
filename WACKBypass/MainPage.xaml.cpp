#include "pch.h"
#include "MainPage.xaml.h"
#include <ppltasks.h>

using namespace WACKBypass;

using namespace concurrency;
using namespace Platform;
using namespace Windows::Foundation;
using namespace Windows::Foundation::Collections;
using namespace Windows::UI::Xaml;
using namespace Windows::UI::Xaml::Controls;
using namespace Windows::UI::Xaml::Controls::Primitives;
using namespace Windows::UI::Xaml::Data;
using namespace Windows::UI::Xaml::Input;
using namespace Windows::UI::Xaml::Media;
using namespace Windows::UI::Xaml::Navigation;

typedef struct _PEB_LDR_DATA
{
	ULONG Length;
	UCHAR Initialized;
	PVOID SsHandle;
	LIST_ENTRY InLoadOrderModuleList;
	LIST_ENTRY InMemoryOrderModuleList;
	LIST_ENTRY InInitializationOrderModuleList;
	PVOID EntryInProgress;
} PEB_LDR_DATA, *PPEB_LDR_DATA;

typedef struct _PEB
{
	BYTE Reserved1[2];
	BYTE BeingDebugged;
	BYTE Reserved2[1];
	PVOID Reserved3[2];
	PPEB_LDR_DATA Ldr;
	PVOID ProcessParameters;
	PVOID Reserved4[3];
	PVOID AtlThunkSListPtr;
	PVOID Reserved5;
	ULONG Reserved6;
	PVOID Reserved7;
	ULONG Reserved8;
	ULONG AtlThunkSListPtr32;
	PVOID Reserved9[45];
	BYTE Reserved10[96];
	PVOID PostProcessInitRoutine;
	BYTE Reserved11[128];
	PVOID Reserved12[1];
	ULONG SessionId;
} PEB, *PPEB;

typedef struct _TEB
{
	PVOID Reserved1[12];
	PPEB ProcessEnvironmentBlock;
	PVOID Reserved2[399];
	BYTE Reserved3[1952];
	PVOID TlsSlots[64];
	BYTE Reserved4[8];
	PVOID Reserved5[26];
	PVOID ReservedForOle;  // Windows 2000 only
	PVOID Reserved6[4];
	PVOID TlsExpansionSlots;
} TEB, *PTEB;

inline HMODULE GetKernelAddress()
{
	auto teb = NtCurrentTeb();
	auto peb = teb->ProcessEnvironmentBlock;
	auto pebldr = peb->Ldr;
	auto ioml = *(DWORD*)pebldr->InInitializationOrderModuleList.Flink;
	return (HMODULE)*(DWORD*)(ioml + 8);
}

// http://forum.xda-developers.com/showthread.php?t=1944675
HMODULE SearchKernelAddress()
{
	char *Tmp = (char*)GetTickCount64;
	Tmp = (char*)((~0xFFF)&(DWORD_PTR)Tmp);

	while (Tmp)
	{
		__try
		{
			if (Tmp[0] == 'M' && Tmp[1] == 'Z')
				break;
		}
		__except (EXCEPTION_EXECUTE_HANDLER)
		{
		}
		Tmp -= 0x1000;
	}

	if (Tmp == 0)
		return nullptr;
	else 
		return (HMODULE)Tmp;
}

MainPage::MainPage()
{
	InitializeComponent();
}

typedef HMODULE WINAPI
LoadLibraryExWPtr(
	_In_ LPCWSTR lpLibFileName,
	_Reserved_ HANDLE hFile,
	_In_ DWORD dwFlags
	);

typedef WINUSERAPI int WINAPI MessageBoxWPtr(
	_In_opt_ HWND hWnd,
	_In_opt_ LPCWSTR lpText,
	_In_opt_ LPCWSTR lpCaption,
	_In_ UINT uType);


void WACKBypass::MainPage::Page_Loaded(Platform::Object^ sender, Windows::UI::Xaml::RoutedEventArgs^ e)
{
	MEMORY_BASIC_INFORMATION info = {};
	if (VirtualQuery(VirtualQuery, &info, sizeof(info)))
	{
		auto kernelAddr = (HMODULE)info.AllocationBase;
		auto loadlibraryPtr = (int64_t)GetProcAddress(kernelAddr, "LoadLibraryExW");
		VirtualQueryResultText->Text = loadlibraryPtr.ToString();
	}
	auto kernelAddr = GetKernelAddress();
	auto loadlibraryPtr = (int64_t)GetProcAddress(kernelAddr, "LoadLibraryExW");
	TEBResultText->Text = loadlibraryPtr.ToString();
	kernelAddr = SearchKernelAddress();
	loadlibraryPtr = (int64_t)GetProcAddress(kernelAddr, "LoadLibraryExW");
	SearchResultText->Text = loadlibraryPtr.ToString();
	auto loadLibrary = (LoadLibraryExWPtr*)loadlibraryPtr;
	auto user32 = loadLibrary(L"user32.dll", nullptr, 0);
	auto messageBox = (MessageBoxWPtr*)GetProcAddress(user32, "MessageBoxW");
	auto window = Windows::UI::Core::CoreWindow::GetForCurrentThread();
	create_async([messageBox]() {
		messageBox(nullptr, L"Prohibited API loaded.", L"F*ck Microsoft", 0);
	});
}
