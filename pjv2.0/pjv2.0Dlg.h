
// pjv2.0Dlg.h : ͷ�ļ�
//
#pragma warning(disable:4996)
#pragma once

// Cpjv20Dlg �Ի���
class Cpjv20Dlg : public CDialogEx
{
// ����
public:
	Cpjv20Dlg(CWnd* pParent = NULL);	// ��׼���캯��

// �Ի�������
	enum { IDD = IDD_PJV20_DIALOG };

	protected:
	virtual void DoDataExchange(CDataExchange* pDX);	// DDX/DDV ֧��


// ʵ��
protected:
	HICON m_hIcon;

	// ���ɵ���Ϣӳ�亯��
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
