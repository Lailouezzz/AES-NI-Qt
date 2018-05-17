#ifndef QAES256_HEADER
#define QAES256_HEADER
#include <type_traits>
#include <QtCore>

#define CAST_M128I(x) reinterpret_cast<__m128i*>(x)
#define CONSTCAST_M128I(x) reinterpret_cast<const __m128i*>(x)
#define CAST_UINT8(x) reinterpret_cast<quint8*>(x)
#define CONSTCAST_UINT8(x) reinterpret_cast<const quint8*>(x)
#define CAST_CHAR8(x) reinterpret_cast<char*>(x)
#define CONSTCAST_CHAR8(x) reinterpret_cast<const char*>(x)



class QAES256 : public QObject
{
	Q_OBJECT
public:

	enum AESMode
	{
		ECB,
		CBC
	};
	constexpr static int AES_BLOCK_SIZE = 16;
	static constexpr int AES_KEY_SIZE = 256;
	static constexpr int AES_SIZE_EXPKEY = ((AES_KEY_SIZE / 8) / 4) + 7;




	QAES256(const AESMode& encryptMode);
	QAES256(const AESMode& encryptMode, const QByteArray& userKey);
	QAES256() = delete;


	void reset();
	bool setIv(const QByteArray& iv) { if (iv.size() == AES_BLOCK_SIZE) { std::memcpy(&m_currentIv, iv.data(), AES_BLOCK_SIZE); return true; } else return false; }
	void setMode(const AESMode& mode) { m_encryptMode = mode; }
	void setKey(const QByteArray& userKey) { aesSheduleKey256(CONSTCAST_M128I(userKey.data())); }
	AESMode getMode() const { return m_encryptMode; }

	QByteArray encrypt(QByteArray data);
	QByteArray encryptFinal();
	QByteArray decrypt(QByteArray data);
	void removePadding(QByteArray& data); // Remove padding of block


protected:

	void aesSheduleKey256(const __m128i* userKey); // Setup m_keyEnc/Dec
	void cipher(__m128i& inout) const
	{
		inout = _mm_xor_si128(inout, m_keyEnc[0]);
		for (quint8 i = 1; i < AES_SIZE_EXPKEY - 1; i++)
		{
			inout = _mm_aesenc_si128(inout, m_keyEnc[i]);
		}
		inout = _mm_aesenclast_si128(inout, m_keyEnc[AES_SIZE_EXPKEY - 1]);
	}
	void invCipher(__m128i& inout) const
	{
		inout = _mm_xor_si128(inout, m_keyDec[0]);
		for (quint8 i = 1; i < AES_SIZE_EXPKEY - 1; i++)
		{
			inout = _mm_aesdec_si128(inout, m_keyDec[i]);
		}
		inout = _mm_aesdeclast_si128(inout, m_keyDec[AES_SIZE_EXPKEY - 1]);
	}

private:

	AESMode m_encryptMode;
	__m128i m_keyEnc[AES_SIZE_EXPKEY];
	__m128i m_keyDec[AES_SIZE_EXPKEY];
	__m128i m_currentIv;
	__m128i m_waitingData;
	int m_waitingDataSize;



	__m128i aes_128_key_expansion(__m128i key, __m128i key_with_rcon) const;
	__m128i aes_256_key_expansion(__m128i key, __m128i key2) const;

};
#endif
