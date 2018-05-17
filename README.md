# AES-NI-Qt
AES-NI implementation in C++ with Qt.

## Usage

To use it input QAES256.cpp/h in your project.

### Create QAES256 and use it

To create QAES256 object you have 2 way :

```cpp
QAES256(const AESMode& encryptMode);
```

`AESMode` is enum at this time, ECB and CBC (you can learn that on wikipedia) mode are implemented.

```cpp
QAES256(const AESMode& encryptMode, const QByteArray& userKey);
```

The `QByteArray` is the user key who go expand, `userKey.size() == QAES256::AES_KEY_SIZE / 8`.

```cpp
void setKey(const QByteArray& userKey);
```

The `QByteArray` is the user key who go expand, `userKey.size() == QAES256::AES_KEY_SIZE / 8`.

```cpp
bool setIv(const QByteArray& iv);
```

The `QByteArray` is the initialize vector (at this time used only by the CBC mode), don't use the same iv always.
The iv must be set before encrypt loop or decrypt loop.

```cpp
void reset()
```

ALWAY reset after encrypt loop or decrypt loop.

```cpp
void setMode(const AESMode& mode) { m_encryptMode = mode; }
```

`AESMode` is enum at this time, ECB and CBC (you can learn that on wikipedia) mode are implemented.

```cpp
AESMode getMode() { return m_encryptMode; }
```

Return the actual mode.

```cpp
QByteArray encrypt(QByteArray data);
```

Return the contents of data encrypted.

```cpp
QByteArray encryptFinal();
```

Return the last block with the padding. (my padding method is : {myData}, 1, 0, 0... with this method it's easy to remove the padding)

```cpp
QByteArray decrypt(QByteArray data);
```

Return the contents of data decrypted.

```cpp
void removePadding(QByteArray& data);
```

This function remove the padding of data, definition : 
```cpp
void QAES256::removePadding(QByteArray& data)
{										//   1 and 0s of the encryptFinal function
	data.truncate(data.lastIndexOf(1)); // for remove padding ex if the last block is : |M|y|D|a|t|a|t|e|s|t|1|0|0|0|0|0|
}								// This function remove this |1|0|0|0|0|0| for make : MyDatatest
```

### Encryption/Decryption example

Take the example with the comments that explains the function for the ECB mode:

```cpp
QByteArray userKey("MyKey"); // Create key

// hash key for getting 256 bits key
QAES256 aes(QAES256::ECB, QCryptographicHash::hash(userKey, QCryptographicHash::Sha256));

																						  // The data to encrypt
QByteArray myData("My secret data");
QByteArray dataE = aes.encrypt(myData); // Encrypt data
dataE.push_back(aes.encryptFinal()); // Finish the encrypt (add padding and the last block)

qDebug() << "Cipher data : " << dataE;

aes.reset(); // Reset cipher
QByteArray dataD = aes.decrypt(dataE); // Decrypt the crypted data


qDebug() << "With padding : " << dataD;


aes.removePadding(dataD); // Remove padding
qDebug() << "Without padding : " << dataD;
```

OUTPUT :

```
Cipher data :  "\x97^\xBD\x7F\x19}\x13]\bhx_\x96\xB3\xC8k"
With padding :  "My secret data\x01\x00"
Without padding :  "My secret data"
```
