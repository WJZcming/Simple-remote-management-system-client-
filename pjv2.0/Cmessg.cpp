// Cmessg.cpp : 实现文件
//

#include "stdafx.h"
#include "Cmessg.h"
#include "afxdialogex.h"


// Cmessg 对话框

IMPLEMENT_DYNAMIC(Cmessg, CDialogEx)

Cmessg::Cmessg(CWnd* pParent /*=NULL*/)
	: CDialogEx(Cmessg::IDD, pParent)
{

}

Cmessg::~Cmessg()
{
}

void Cmessg::DoDataExchange(CDataExchange* pDX)
{
	CDialogEx::DoDataExchange(pDX);
}


BEGIN_MESSAGE_MAP(Cmessg, CDialogEx)
END_MESSAGE_MAP()


// Cmessg 消息处理程序


BOOL Cmessg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  在此添加额外的初始化
	ModifyStyleEx(WS_EX_APPWINDOW, WS_EX_TOOLWINDOW);
	return TRUE;  // return TRUE unless you set the focus to a control
	// 异常:  OCX 属性页应返回 FALSE
}
