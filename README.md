# AES-NI-Qt
AES-NI implementation in C++ with Qt

## Usage

To use it input QAES256.cpp/h in your project

### Create QAES256 and use it

To create QAES256 object you have 2 way :

```cpp
QAES256(const AESMode& encryptMode);
```

`AESMode` is enum at this time, ECB and CBC mode are implemented

```cpp
QAES256(const AESMode& encryptMode, const QByteArray& userKey);
```

The `QByteArray` it's the user key who go expand, `userKey.size() == QAES256::AES_KEY_SIZE / 8`

#### encryption

