#ifndef __STRING_H_ZXK_20100410
#define __STRING_H_ZXK_20100410

#ifdef __cplusplus
extern "C" {
#endif

typedef struct
{
	unsigned short  Length;
	unsigned short  MaximumLength;
	wchar_t*  Buffer;
} UNICODE_STRING, *PUNICODE_STRING;

//转换时间格式
LPSTR SystemTimeToString( SYSTEMTIME* tmSystem, OUT LPSTR lpszDatatime, 
						  unsigned int cbBufferSize  );

/*
Description:		分割字符串
Parameter:			lpszSrc	 所要分割的字符串
chSplit  分隔字符
aString	 分割结果，字符串数组的指针
cbMaxInRow	每一个字符串一行中最大字符数
pnMaxRow	分割了多少行
Return:				TRUE	 分割成功
FALSE	 分割失败
*/
BOOL	SplitString( LPCTSTR lpszSrc, char chSplit, OUT char* aString, 
					 int cbMaxInRow, int* pnMaxRow );

BOOL	BufferToHexString( IN PBYTE pBuffer, IN DWORD cbBufSize, 
						  OUT char* pHexStr, OUT DWORD cbStrSize );

int		HexStringToBuffer( IN LPCSTR pHexString, IN PBYTE pBuffer, 
							DWORD cbBufSize );

//删除字符串左侧的空格
void		TrimLeftString( LPSTR lpsz );

//删除字符串右侧的空格
void		TrimRightString( LPSTR lpsz );

int		CombinString( char chSplit, OUT char* aString, int cbMaxInRow, int nRow, OUT LPSTR lpszDst, int nLenDst );

typedef struct _IP_STRING{
	char szIP[16];
}IP_STRING, *PIP_STRING;

LPCSTR GetIPString( DWORD ip, PIP_STRING strip );

/*
Description:	获取MAC地址格式的字符串
Parameter:		pMac			MAC地址的值（6个字节)
lpszMac			MAC字符串
cbStrSize		MAC字符串缓冲区长度
Return:			LPCTSTR			返回MAC字符串	
*/
LPCTSTR GetMacString( PBYTE pMac, LPSTR lpszMac, DWORD cbStrSize );

#ifdef __cplusplus
}
#endif

#endif //__STRING_H_ZXK_20100410


