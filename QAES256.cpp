#include "QAES256.h"

/*
Member :

AESMode m_encryptMode;
__m128i m_keyEnc[AES_SIZE_EXPKEY];
__m128i m_keyDec[AES_SIZE_EXPKEY];
__m128i m_currentIv;
__m128i m_waitingData;
int m_waitingDataSize;
*/

QAES256::QAES256(const AESMode& encryptMode)
	:
	m_encryptMode(encryptMode),
	m_waitingDataSize(0)
{
}

QAES256::QAES256(const AESMode& encryptMode, const QByteArray& userKey)
	:
	m_encryptMode(encryptMode),
	m_waitingDataSize(0)
{
	setKey(userKey);
}

void QAES256::reset()
{
	m_waitingDataSize = 0;
}

QByteArray QAES256::encrypt(QByteArray data)
{
	QByteArray retData;

	// If we have a waiting data make front input in data
	if (m_waitingDataSize != 0)
	{
		data.insert(0, CONSTCAST_CHAR8(&m_waitingData), m_waitingDataSize);
		m_waitingDataSize = 0;
	}


	for (quint64 i = 0; i < data.size(); i += AES_BLOCK_SIZE)
	{
		// If the actual block is smaller than AES_BLOCK_SIZE
		if (i + AES_BLOCK_SIZE > data.size())
		{
			m_waitingDataSize = AES_BLOCK_SIZE - ((i + AES_BLOCK_SIZE) - data.size());
			// "memcpy"
			for (int j = 0; j < m_waitingDataSize; j++)
			{
				CAST_UINT8(&m_waitingData)[j] = data[static_cast<uint>(j + i)];
			}
			break;
		}
		// Load state
		__m128i bufState = _mm_loadu_si128(CAST_M128I(data.data() + i));
		switch (m_encryptMode)
		{
		case ECB:
			cipher(bufState);
			retData.insert(i, CAST_CHAR8(&bufState), sizeof(bufState));
			break;
		case CBC:
			bufState = _mm_xor_si128(bufState, m_currentIv);
			cipher(bufState);
			m_currentIv = _mm_loadu_si128(&bufState);
			retData.insert(i, CAST_CHAR8(&bufState), sizeof(bufState));
			break;
		default:
			break;
		}
	}
	return retData;
}

QByteArray QAES256::encryptFinal()
{
	// Make QByteArray with waiting data
	QByteArray retData(CAST_CHAR8(&m_waitingData), m_waitingDataSize);
	m_waitingDataSize = 0;
	// Push 1 for the padding
	retData.push_back(1);
	int pos1 = retData.size();
	// Resize for obtain retData.size() % AES_BLOCK_SIZE == 0
	retData.resize(retData.size() + (AES_BLOCK_SIZE - (retData.size() % AES_BLOCK_SIZE)));
	std::memset(retData.data() + pos1, 0, retData.size() - pos1); // memset for padding ex : 1, 0, 0, 0 ...
	return encrypt(retData); // return encrypt final block
}

QByteArray QAES256::decrypt(QByteArray data)
{
	QByteArray retData;


	// If we have a waiting data make front input in data
	if (m_waitingDataSize != 0)
	{
		data.insert(0, CAST_CHAR8(&m_waitingData), m_waitingDataSize);
		m_waitingDataSize = 0;
	}

	for (quint64 i = 0; i < data.size(); i += AES_BLOCK_SIZE)
	{
		// If the actual block is smaller than AES_BLOCK_SIZE
		if (i + AES_BLOCK_SIZE > data.size())
		{
			m_waitingDataSize = AES_BLOCK_SIZE - ((i + AES_BLOCK_SIZE) - data.size());
			// "memcpy"
			for (int j = 0; j < m_waitingDataSize; j++)
			{
				CAST_UINT8(&m_waitingData)[j] = data[static_cast<uint>(j + i)];
			}
			break;
		}
		// Load state
		__m128i bufState = _mm_loadu_si128(CAST_M128I(data.data() + i));
		switch (m_encryptMode)
		{
		case ECB:
			invCipher(bufState);
			retData.insert(i, CAST_CHAR8(&bufState), sizeof(bufState));
			break;
		case CBC:
		{
			__m128i tempState = m_currentIv;
			m_currentIv = bufState;
			invCipher(bufState);
			bufState = _mm_xor_si128(bufState, tempState);
			retData.insert(i, CAST_CHAR8(&bufState), sizeof(bufState));
		}
		break;
		default:
			break;
		}
	}
	return retData;
}

void QAES256::removePadding(QByteArray& data)
{																										//   1 and 0 of the encryptFinal function
	data.truncate(data.lastIndexOf(1)); // for remove padding ex if the last block is : |M|y|D|a|t|a|t|e|s|t|1|0|0|0|0|0|
}																			   // This function remove this |1|0|0|0|0|0| for make : MyDatatest

__m128i QAES256::aes_128_key_expansion(__m128i key, __m128i key_with_rcon) const
{
	key_with_rcon = _mm_shuffle_epi32(key_with_rcon, _MM_SHUFFLE(3, 3, 3, 3));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	return _mm_xor_si128(key, key_with_rcon);
}

__m128i QAES256::aes_256_key_expansion(__m128i key, __m128i key2) const
{
	__m128i key_with_rcon = _mm_aeskeygenassist_si128(key2, 0x00);

	key_with_rcon = _mm_shuffle_epi32(key_with_rcon, _MM_SHUFFLE(2, 2, 2, 2));

	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	key = _mm_xor_si128(key, _mm_slli_si128(key, 4));
	return _mm_xor_si128(key, key_with_rcon);
}

void QAES256::aesSheduleKey256(const __m128i* userKey)
{
	// Gen key
	const __m128i K0 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(userKey));
	const __m128i K1 = _mm_loadu_si128(reinterpret_cast<const __m128i*>(userKey + 16));

	const __m128i K2 = aes_128_key_expansion(K0, _mm_aeskeygenassist_si128(K1, 0x01));
	const __m128i K3 = aes_256_key_expansion(K1, K2);

	const __m128i K4 = aes_128_key_expansion(K2, _mm_aeskeygenassist_si128(K3, 0x02));
	const __m128i K5 = aes_256_key_expansion(K3, K4);

	const __m128i K6 = aes_128_key_expansion(K4, _mm_aeskeygenassist_si128(K5, 0x04));
	const __m128i K7 = aes_256_key_expansion(K5, K6);

	const __m128i K8 = aes_128_key_expansion(K6, _mm_aeskeygenassist_si128(K7, 0x08));
	const __m128i K9 = aes_256_key_expansion(K7, K8);

	const __m128i K10 = aes_128_key_expansion(K8, _mm_aeskeygenassist_si128(K9, 0x10));
	const __m128i K11 = aes_256_key_expansion(K9, K10);

	const __m128i K12 = aes_128_key_expansion(K10, _mm_aeskeygenassist_si128(K11, 0x20));
	const __m128i K13 = aes_256_key_expansion(K11, K12);

	const __m128i K14 = aes_128_key_expansion(K12, _mm_aeskeygenassist_si128(K13, 0x40));


	// Store key for enc
	_mm_storeu_si128(m_keyEnc + 0, K0);
	_mm_storeu_si128(m_keyEnc + 1, K1);
	_mm_storeu_si128(m_keyEnc + 2, K2);
	_mm_storeu_si128(m_keyEnc + 3, K3);
	_mm_storeu_si128(m_keyEnc + 4, K4);
	_mm_storeu_si128(m_keyEnc + 5, K5);
	_mm_storeu_si128(m_keyEnc + 6, K6);
	_mm_storeu_si128(m_keyEnc + 7, K7);
	_mm_storeu_si128(m_keyEnc + 8, K8);
	_mm_storeu_si128(m_keyEnc + 9, K9);
	_mm_storeu_si128(m_keyEnc + 10, K10);
	_mm_storeu_si128(m_keyEnc + 11, K11);
	_mm_storeu_si128(m_keyEnc + 12, K12);
	_mm_storeu_si128(m_keyEnc + 13, K13);
	_mm_storeu_si128(m_keyEnc + 14, K14);

	// Store key for dec
	_mm_storeu_si128(m_keyDec + 0, K14);
	_mm_storeu_si128(m_keyDec + 1, _mm_aesimc_si128(K13));
	_mm_storeu_si128(m_keyDec + 2, _mm_aesimc_si128(K12));
	_mm_storeu_si128(m_keyDec + 3, _mm_aesimc_si128(K11));
	_mm_storeu_si128(m_keyDec + 4, _mm_aesimc_si128(K10));
	_mm_storeu_si128(m_keyDec + 5, _mm_aesimc_si128(K9));
	_mm_storeu_si128(m_keyDec + 6, _mm_aesimc_si128(K8));
	_mm_storeu_si128(m_keyDec + 7, _mm_aesimc_si128(K7));
	_mm_storeu_si128(m_keyDec + 8, _mm_aesimc_si128(K6));
	_mm_storeu_si128(m_keyDec + 9, _mm_aesimc_si128(K5));
	_mm_storeu_si128(m_keyDec + 10, _mm_aesimc_si128(K4));
	_mm_storeu_si128(m_keyDec + 11, _mm_aesimc_si128(K3));
	_mm_storeu_si128(m_keyDec + 12, _mm_aesimc_si128(K2));
	_mm_storeu_si128(m_keyDec + 13, _mm_aesimc_si128(K1));
	_mm_storeu_si128(m_keyDec + 14, K0);
}