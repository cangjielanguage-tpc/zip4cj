/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2024. All rights reserved.
 */
package zip4cj.crypto

public interface Decrypter {
    func decryptData(buff: Array<UInt8>): Int64
}
