/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2024. All rights reserved.
 */
package zip4cj.io.outputstream

abstract class ICipherOutputStream <: OutputStream & Resource {

    public func write(b: Array<UInt8>): Unit

    public func writeHeaders(b: Array<UInt8>): Unit

    public func closeEntry(): Unit

    public func close(): Unit

    public func isClosed(): Bool

    public func getNumberOfBytesWrittenForThisEntry(): Int64
}

// NOTE: this class must NOT be generic. cjc (release/-O2, dynamic library)
// mis-binds the reified specialization CipherOutputStream<G>.write for
// cross-package type arguments to the same-package NoEncrypter
// specialization, which silently skips encryption of entry data
// (see test_zipFile_24 pipeline failure). Keeping `encrypter` as a plain
// Encrypter interface reference avoids reified specialization entirely.
abstract class CipherOutputStream <: ICipherOutputStream {
    protected var outputStream: ZipEntryOutputStream
    protected var zipParameters: ZipParameters
    protected var password: ?Array<Rune>
    protected var useUtf8ForPassword: Bool
    protected var encrypter: ?Encrypter = None
    var closed = false
    public init(
        zipEntryOutputStream: ZipEntryOutputStream,
        zipParameters: ZipParameters,
        password: ?Array<Rune>,
        useUtf8ForPassword: Bool
    ) {
        this.outputStream = zipEntryOutputStream
        this.zipParameters = zipParameters
        this.password = password
        this.useUtf8ForPassword = useUtf8ForPassword
    }

    public open func write(b: Array<UInt8>): Unit {
        match (encrypter) {
            case Some(e) => e.encryptData(b)
            case None => throw ZipException("encrypter is not initialized")
        }
        this.outputStream.write(b)
    }

    public open func writeHeaders(b: Array<UInt8>): Unit {
        this.outputStream.write(b)
    }

    public open func closeEntry(): Unit {
        this.outputStream.closeEntry()
    }

    public open func close(): Unit {
        this.outputStream.close()
        closed = true
    }

    public open func isClosed(): Bool {
        if (let Some(v) <- (outputStream as Resource)) {
            v.isClosed()
        } else {
            closed
        }
    }

    public open func getNumberOfBytesWrittenForThisEntry(): Int64 {
        return this.outputStream.getNumberOfBytesWrittenForThisEntry()
    }

    public open func flush(): Unit {
        return
    }
}
