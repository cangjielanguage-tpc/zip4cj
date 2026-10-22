/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2024. All rights reserved.
 */
package zip4cj.io.outputstream

class ZipStandardCipherOutputStream <: CipherOutputStream {
    private var pendingBuffer: Array<UInt8> = Array<UInt8>(16, repeat: 0)

    private var pendingBufferLength: Int32 = 0

    public init(
        outputStream: ZipEntryOutputStream,
        zipParameters: ZipParameters,
        password: ?Array<Rune>,
        useUtf8ForPassword: Bool
    ) {
        super(outputStream, zipParameters, password, useUtf8ForPassword)
        if (password.isNone()) {
            throw ZipException("input password is null")
        }
        var key: Int64 = getEncryptionKey(zipParameters)
        var encrypter: StandardEncrypter = StandardEncrypter(password, key, useUtf8ForPassword)
        this.encrypter = encrypter
        writeHeaders(encrypter.getHeaderBytes())
    }

    public override func write(b: Array<UInt8>): Unit {
        super.write(b)
    }

    public func getEncryptionKey(zipParameters: ZipParameters): Int64 {
        if (zipParameters.isWriteExtendedLocalFileHeader()) {
            var dosTime: Int64 = Zip4cjUtil.epochToExtendedDosTime(zipParameters.getLastModifiedFileTime())
            return (dosTime & 0x0000ffff) << 16
        }
        return zipParameters.getEntryCRC()
    }
}
