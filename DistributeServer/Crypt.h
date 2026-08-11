/**************本资源来自互联网 e起玩资源社区提示禁商业 仅学习*******************/
/************更多资源请访问e起玩游戏资源社区(www.code175.com)查询获得***************/


/*****************如需帮助请到e起玩交流总群咨询 QQ群号:63081844*********************/
//////////////////////////////////////////////////////////////////////
//
//// Crypt.h: interface for the CCrypt class.

//
//////////////////////////////////////////////////////////////////////


#if !defined(AFX_CRYPT_H__766AA5A2_1171_40A3_BF8D_06EC44D3F94D__INCLUDED_)
#define AFX_CRYPT_H__766AA5A2_1171_40A3_BF8D_06EC44D3F94D__INCLUDED_

#if _MSC_VER > 1000
#pragma once
#endif // _MSC_VER > 1000

#include "HSEL.h"


class CCrypt  
{
public:
	CCrypt();
	virtual ~CCrypt();

	void			Create();

	void			Init( HselInit	eninit, HselInit deInit );
	HselInit *		GetEnKey(){ return &m_eninit; }
	HselInit *		GetDeKey(){ return &m_deinit; }
	CHSEL_STREAM *	GetEnCHSEL_STREAM() { return &m_hEnStream; }
	CHSEL_STREAM *	GetDeCHSEL_STREAM() { return &m_hDeStream; }

	BOOL			Encrypt( char * eBuf, int bufSize );
	BOOL			Decrypt( char * eBuf, int bufSize );
	char			GetEnCRCConvertChar();
	char			GetDeCRCConvertChar();
	void			SetInit( BOOL val ) { m_bInited = val; }


private:
	HselInit		m_eninit;
	HselInit		m_deinit;
	CHSEL_STREAM	m_hEnStream;

	CHSEL_STREAM	m_hDeStream;
	BOOL			m_bInited;
};

#endif // !defined(AFX_CRYPT_H__766AA5A2_1171_40A3_BF8D_06EC44D3F94D__INCLUDED_)


