
import std.random.*

let random = Random()

abstract class ICipherOutputStream  {
    var kkk = random.nextInt64()
    public open func getClassName(): String {
        return "ICipherOutputStream : ${kkk}"
    }
}

public interface Encrypter {}

public class StandardEncrypter <: Encrypter {}
class NoEncrypter <: Encrypter {}
public class AESEncrypter <: Encrypter {}

abstract class CipherOutputStream<T> <: ICipherOutputStream where T <: Encrypter {

}

class NoCipherOutputStream <: CipherOutputStream<NoEncrypter> {
    var rrr = random.nextInt64()
    public func getClassName(): String {
        return "NoCipherOutputStream : ${rrr}"
    }
}

class ZipStandardCipherOutputStream <: CipherOutputStream<StandardEncrypter> {
    var rrr = random.nextInt64()
    public func getClassName(): String {
        return "ZipStandardCipherOutputStream : ${rrr}"
    }
}

class AesCipherOutputStream <: CipherOutputStream<AESEncrypter> {
    var rrr = random.nextInt64()
    public func getClassName(): String {
        return "AesCipherOutputStream : ${rrr}"
    }
}

main() {
    let temp = ZipStandardCipherOutputStream()
    println(temp.getClassName())
    println((temp as ICipherOutputStream)?.getClassName())
}