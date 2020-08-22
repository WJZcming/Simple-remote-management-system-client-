#pragma once
#include "resource.h"

// Cmessg 对话框

class Cmessg : public CDialogEx
{
	DECLARE_DYNAMIC(Cmessg)

public:
	Cmessg(CWnd* pParent = NULL);   // 标准构造函数
	virtual ~Cmessg();

// 对话框数据
	enum { IDD = IDD_MESS };

protected:
	virtual void DoDataExchange(CDataExchange* pDX);    // DDX/DDV 支持

	DECLARE_MESSAGE_MAP()
public:
	virtual BOOL OnInitDialog();
};
