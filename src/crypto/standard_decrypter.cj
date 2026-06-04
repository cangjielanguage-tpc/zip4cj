/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2024. All rights reserved.
 */
package zip4cj.crypto

public class StandardDecrypter <: Decrypter {
    private var zipCryptoEngine: ZipCryptoEngine

    @OverflowWrapping
    public init(
        password: ?Array<Rune>,
        crc: Int64,
        lastModifiedFileTime: Int64,
        headerBytes: Array<Byte>,
        useUtf8ForPassword: Bool
    ) {
        this.zipCryptoEngine = ZipCryptoEngine()
        if (password.isNone()) {
            throw ZipException("Wrong password!", ZipExceptionType.WRONG_PASSWORD)
        }
        zipCryptoEngine.initKeys(password.getOrThrow(), useUtf8ForPassword)
        var result = headerBytes[0]
        for (i in 0..InternalZipConstants.STD_DEC_HDR_SIZE) {
            let decryptedByte = UInt8(result ^ zipCryptoEngine.decryptByte())
            if (i + 1 == InternalZipConstants.STD_DEC_HDR_SIZE) {
                // Verify the last byte (verification byte)
                // When key is CRC (writeExtendedLocalFileHeader=false): verify CRC high byte (bits 24-31)
                // When key is dosTime (writeExtendedLocalFileHeader=true): verify dosTime hour byte (bits 8-15)
                let expectedCrcByte = UInt8(crc >> 24)
                let expectedDosTimeByte = UInt8(lastModifiedFileTime >> 8)
                if (decryptedByte != expectedCrcByte && decryptedByte != expectedDosTimeByte) {
                    throw ZipException("Wrong password!", ZipExceptionType.WRONG_PASSWORD)
                } else {
                }
            }

            zipCryptoEngine.updateKeys(decryptedByte)

            if (i + 1 != InternalZipConstants.STD_DEC_HDR_SIZE) {
                result = headerBytes[i + 1]
            }
        }
    }

    private func formatBytes(bytes: Array<Byte>): String {
        var result = "["
        for (i in 0..bytes.size) {
            result += UInt32(UInt8(bytes[i])).toString()
            if (i < bytes.size - 1) {
                result += ","
            }
        }
        result += "]"
        return result
    }

    public func decryptData(buff: Array<UInt8>): Int64 {
        if (buff.size > 0) {
            var previewSize = 16
            if (buff.size < 16) {
                previewSize = buff.size
            }
            var preview = "Before: ["
            for (i in 0..previewSize) {
                preview += UInt32(buff[i]).toString()
                if (i < previewSize - 1) {
                    preview += ","
                }
            }
            preview += "]"
        }
        
        for (i in 0..buff.size) {
            var val = buff[i]
            let decryptedVal = UInt8((val ^ zipCryptoEngine.decryptByte()) & 0xff)
            zipCryptoEngine.updateKeys(decryptedVal)
            buff[i] = decryptedVal
        }
        
        // Print first few bytes after decryption
        if (buff.size > 0) {
            var previewSize = 16
            if (buff.size < 16) {
                previewSize = buff.size
            }
            var preview = "After: ["
            for (i in 0..previewSize) {
                preview += UInt32(buff[i]).toString()
                if (i < previewSize - 1) {
                    preview += ","
                }
            }
            preview += "]"
        }
        
        return buff.size
    }
}
