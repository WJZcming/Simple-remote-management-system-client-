// Cmessg.cpp : ʵ���ļ�
//

#include "stdafx.h"
#include "Cmessg.h"
#include "afxdialogex.h"


// Cmessg �Ի���

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


// Cmessg ��Ϣ�������


BOOL Cmessg::OnInitDialog()
{
	CDialogEx::OnInitDialog();

	// TODO:  �ڴ���Ӷ���ĳ�ʼ��
	ModifyStyleEx(WS_EX_APPWINDOW, WS_EX_TOOLWINDOW);
	return TRUE;  // return TRUE unless you set the focus to a control
	// �쳣:  OCX ����ҳӦ���� FALSE
}
