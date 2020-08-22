
// pjv2.0Dlg.h : 头文件
//
#pragma warning(disable:4996)
#pragma once

// Cpjv20Dlg 对话框
class Cpjv20Dlg : public CDialogEx
{
// 构造
public:
	Cpjv20Dlg(CWnd* pParent = NULL);	// 标准构造函数

// 对话框数据
	enum { IDD = IDD_PJV20_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV 支持


// 实现
protected:
	HICON m_hIcon;

	// 生成的消息映射函数
	virtual BOOL OnInitDialog();
	afx_msg void OnPaint();
	afx_msg HCURSOR OnQueryDragIcon();
	DECLARE_MESSAGE_MAP()
public:
	afx_msg void OnBnClickedButton1();
	afx_msg void OnWindowPosChanging(WINDOWPOS* lpwndpos);
	afx_msg void OnTimer(UINT_PTR nIDEvent);
	//afx_msg void fileview(SOCKET sclient);
	afx_msg void OnDestroy();
};
