#pragma warning(disable:4996)
#include <wtypes.h>
#include <stdio.h>
#include "string.h"

LPSTR	SystemTimeToString( SYSTEMTIME* tmSystem, OUT LPSTR lpszDatatime, 
						    DWORD cbBufferSize  )
{
	if( lpszDatatime == NULL || IsBadWritePtr( lpszDatatime, cbBufferSize ) )  
		return NULL;
	ZeroMemory( lpszDatatime, cbBufferSize );
	_snprintf( lpszDatatime, cbBufferSize - 1, "%d-%02d-%02d %02d:%02d:%02d", 
		tmSystem->wYear,  tmSystem->wMonth, tmSystem->wDay, 
		tmSystem->wHour, tmSystem->wMinute, tmSystem->wSecond );
	return lpszDatatime;
}

BOOL	SplitString( LPCTSTR lpszSrc, char chSplit, OUT char* aString, int cbMaxInRow, int* pnMaxRow )
{
	int nLenSrc = 0;
	int nRow = 0;
	int nColumn = 0;
	int i=0;

	if( lpszSrc == NULL || IsBadStringPtr( lpszSrc, -1 ) ) {
		SetLastError( ERROR_INVALID_PARAMETER );
		return FALSE;
	}

	if( pnMaxRow == NULL || IsBadWritePtr( pnMaxRow, sizeof( int ) ) ) {
		SetLastError( ERROR_INVALID_PARAMETER );
		return FALSE;
	}

	if( aString == NULL || IsBadWritePtr( aString, cbMaxInRow * (*pnMaxRow) ) ) {
		SetLastError( ERROR_INVALID_USER_BUFFER );
		return FALSE;
	}

	nLenSrc = (int)strlen( lpszSrc );
	if( nLenSrc == 0 ) {
		*pnMaxRow = 0;
		return TRUE;
	}

	for( ; i < nLenSrc; i++ ) {
		if( lpszSrc[i] == chSplit ) {
			//说明有新行了
			nRow++;
			nColumn = 0;
			if( nRow >= ( *pnMaxRow ) ) {
				SetLastError( ERROR_INSUFFICIENT_BUFFER );
				return FALSE;
			}
		}
		else {

			if( nColumn >= ( cbMaxInRow - 1 ) ) {
				SetLastError( ERROR_OUT_OF_STRUCTURES );
				return FALSE;
			}
			*(aString + nRow*cbMaxInRow + nColumn ) = *(((char*)lpszSrc) + i );
			nColumn++;
		}
	}

	(*pnMaxRow) = nRow + 1 ;

	return TRUE;
}



BOOL	BufferToHexString( IN PBYTE pBuffer, IN DWORD cbBufSize, OUT char* pHexStr, OUT DWORD cbStrSize )
{
	DWORD i=0;
	if( pBuffer == NULL || IsBadReadPtr( pBuffer, cbBufSize )  )
		return FALSE;

	if( pHexStr == NULL || IsBadWritePtr( pHexStr, cbStrSize ) )
		return FALSE;

	ZeroMemory( pHexStr, cbStrSize );
	for( ; i < cbBufSize; i++ ) {
		char szTmp[3] = {0}; 
		_snprintf( szTmp, sizeof( szTmp), "%02X", pBuffer[i] );
		strncat( pHexStr, szTmp, sizeof( szTmp ) - 1 );
	}

	return TRUE;
}

int	HexStringToBuffer( IN LPCSTR pHexString, IN PBYTE pBuffer, DWORD cbBufSize )
{
	int nLen = (int)strlen( pHexString );
	int i = 0;
	for( i=0; i < ( nLen / 2) &&  i < (int)cbBufSize ; i++ ) {
		char szTmp[3] = {0};
		strncpy( szTmp, pHexString + i*2, 2 );
		pBuffer[i] = (BYTE)strtoul( szTmp, NULL, 16 );
	}

	return i;
}

LPCSTR	GetIPString( DWORD ip, PIP_STRING strip )
{
	_snprintf( strip->szIP, sizeof( strip->szIP) - 1 , "%u.%u.%u.%u", *(PBYTE)&ip, *((PBYTE)&ip+1), *((PBYTE)&ip+2), *((PBYTE)&ip+3) );
	return strip->szIP;
}

/*
Description:	删除字符串左边的空格
Parameter：		lpsz			字符串
*/
void	TrimLeftString( LPSTR lpsz )
{
	char* pString = lpsz;
	int nBlank = 0;
	int i=0;

	if( strlen( lpsz ) <=0 ) 
		return;

	//删除前面的空格
	while( TRUE ) {
		if( pString[i] == ' ' ) {
			nBlank++;
			i++;
		} else {
			//不为空格
			break;
		}
	}

	if( nBlank != 0 ) {
		//有空格
		int nCopy = (int)strlen( lpsz ) - nBlank;
		if( nCopy == 0 ) {
			//全部是空格
			lpsz[0] = 0;
		}
		strncpy( lpsz, pString + nBlank, nCopy );
	}
}

/*
	删除字符串右边的空格
 */
void	TrimRightString( LPSTR lpsz )
{
	char*	pString = lpsz;
	size_t	len = strlen( lpsz );
	if( len <= 0 ) 
		return;

	do{
		if( lpsz[len - 1] == 0x20 ) {
			lpsz[len-1] = 0;
		} else {
			break;
		}
	}while( len--);
}

int	CombinString( char chSplit, OUT char* aString, int cbMaxInRow, int nRow, OUT LPSTR lpszDst, int nLenDst )
{

	int nWritePos = 0;
	int i, j;

	if( aString == NULL || IsBadReadPtr( aString, cbMaxInRow * nRow ) ) {
		SetLastError( ERROR_INVALID_USER_BUFFER );
		return FALSE;
	}

	for(  i=0; i < nRow ; i++ ) {
		for( j=0; j < cbMaxInRow; j++ ) {
			if( *( aString + i*cbMaxInRow + j) != '\0' ) {
				if( nWritePos >= nLenDst ) {
					SetLastError( ERROR_INSUFFICIENT_BUFFER );
					return 0;
				}
				lpszDst[nWritePos] = ( *( aString + i*cbMaxInRow + j ) );
				nWritePos++;
			} else {
				//填充一个分隔字符
				if( nWritePos >= nLenDst ) {
					SetLastError( ERROR_INSUFFICIENT_BUFFER );
					return 0;
				}
				lpszDst[nWritePos] = chSplit;
				nWritePos++;
				break;
			}
		}
	}

	return nWritePos;
}

/*
Description:	获取MAC地址格式的字符串
Parameter:		pMac			MAC地址的值（6个字节)
lpszMac			MAC字符串
cbStrSize		MAC字符串缓冲区长度
Return:			LPCTSTR			返回MAC字符串	
*/
LPCTSTR GetMacString( PBYTE pMac, LPSTR lpszMac, DWORD cbStrSize )
{
	_snprintf( lpszMac, cbStrSize - 1, "%02X-%02X-%02X-%02X-%02X-%02X", 
		pMac[0], pMac[1], pMac[2], pMac[3], pMac[4], pMac[5] );
	return lpszMac;
}

