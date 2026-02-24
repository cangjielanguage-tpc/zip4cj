/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2024. All rights reserved.
 */
package zip4cj.io.outputstream

open class CompressedOutputStream <: OutputStream & Resource {
    var random: Int64 = random.nextInt64()
    private let cipherOutputStream: ICipherOutputStream
    public init(cipherOutputStream: ICipherOutputStream) {
        this.cipherOutputStream = cipherOutputStream
        println("----------6: ${cipherOutputStream.get123()}, random: ${random}")
    }

    public open func write(b: Array<UInt8>): Unit {
        println("CompressedOutputStream.write: ${b}, cipherOutputStream class: ${cipherOutputStream.get123()}, random: ${random}")
        cipherOutputStream.write(b)
    }

    public open func closeEntry(): Unit {
        cipherOutputStream.closeEntry()
    }

    public open func close(): Unit {
        cipherOutputStream.close()
    }

    public open func isClosed(): Bool {
        (cipherOutputStream as Resource).getOrThrow().isClosed()
    }

    public open func getCompressedSize(): Int64 {
        return cipherOutputStream.getNumberOfBytesWrittenForThisEntry()
    }

    public open func flush(): Unit {}
}
