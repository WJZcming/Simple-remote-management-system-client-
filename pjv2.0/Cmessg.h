#pragma once
#include "resource.h"

// Cmessg �Ի���

class Cmessg : public CDialogEx
{
	DECLARE_DYNAMIC(Cmessg)

public:
	Cmessg(CWnd* pParent = NULL);   // ��׼���캯��
	virtual ~Cmessg();

// �Ի�������
	enum { IDD = IDD_MESS };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV ֧��

	DECLARE_MESSAGE_MAP()
public:
	virtual BOOL OnInitDialog();
};
