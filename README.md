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
ALWAY reset after encrypt loop or decrypt loop

```cpp
void setMode(const AESMode& mode) { m_encryptMode = mode; }
```

`AESMode` is enum at this time, ECB and CBC (you can learn that on wikipedia) mode are implemented.

```cpp
AESMode getMode() { return m_encryptMode; }
```

Return the actual mode.

#### Encryption example

