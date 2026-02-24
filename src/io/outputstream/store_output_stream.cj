/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2024. All rights reserved.
 */
package zip4cj.io.outputstream

class StoreOutputStream <: CompressedOutputStream {
    public init(cipherOutputStream: NoCipherOutputStream) {
        super(cipherOutputStream)
    }

    public init(cipherOutputStream: AesCipherOutputStream) {
        super(cipherOutputStream)
    }
    public init(cipherOutputStream: ZipStandardCipherOutputStream) {
        super(cipherOutputStream)
        println("----------5: ${cipherOutputStream.get123()}")
    }
}
