/*
 * Copyright (c) Huawei Technologies Co., Ltd. 2022-2024. All rights reserved.
 */
package zip4cj.tasks

import std.fs.*

@When[os != "Windows"]
import std.posix.symlink

// 符号链接目标的合理长度上限(超出视为恶意/损坏条目)
let MAX_SYMLINK_TARGET_SIZE: Int64 = 65536

public abstract class AbstractExtractFileTask<T> <: AsyncZipTask<T> {
    private let zipModel: ZipModel
    private let unzipParameters: UnzipParameters

    public init(zipModel: ZipModel, unzipParameters: UnzipParameters, asyncTaskParameters: AsyncTaskParameters) {
        super(asyncTaskParameters)
        this.zipModel = zipModel
        this.unzipParameters = unzipParameters
    }

    protected func extractFile(
        zipInputStream: ZipInputStream,
        fileHeader: FileHeader,
        output: String,
        newFileName: ?String,
        progressMonitor: ProgressMonitor,
        readBuff: Array<Byte>
    ) {
        var outputPath = output
        var isSymbolicLink = isSymbolicLink(fileHeader)
        if (isSymbolicLink && !unzipParameters.isExtractSymbolicLinks()) {
            return
        }
        if (!outputPath.endsWith(Path.Separator)) {
            outputPath = "${outputPath}${Path.Separator}"
        }
        var outputFile: Path = determineOutputFile(fileHeader, outputPath, newFileName)
        // progressMonitor.setFileName(outputFile.toCanonical().toString()) // Fix Run it later, there will be an error when running here
        progressMonitor.setFileName(outputFile.toString())
        // TODO assertCanonicalPathsAreSame
        verifyNextEntry(zipInputStream, fileHeader)
        if (fileHeader.isDirectory()) {
            if (!exists(outputFile)) {
                Directory.create(outputFile, recursive: true)
            }
        } else if (isSymbolicLink) {
            createSymLink(zipInputStream, fileHeader, outputFile, Path(outputPath), progressMonitor, readBuff)
        } else {
            checkOutputDirectoryStructure(outputFile)
            unzipFile(zipInputStream, outputFile, progressMonitor, readBuff)
        }

        if (!isSymbolicLink) {
            UnzipUtil.applyFileAttributes(fileHeader, outputFile)
        }
    }

    protected func isSymbolicLink(fileHeader: FileHeader): Bool {
        var externalFileAttributes = fileHeader.getExternalFileAttributes()
        if (externalFileAttributes.isNone() || externalFileAttributes.getOrThrow().size < 4) {
            return false
        }
        return BitUtils.isBitSet(externalFileAttributes.getOrThrow()[3], 5)
    }

    private func unzipFile(
        inputStream: ZipInputStream,
        outputFile: Path,
        progressMonitor: ProgressMonitor,
        buff: Array<Byte>
    ) {
        if (!exists(outputFile.parent)) {
            Directory.create(outputFile.parent, recursive: true)
        }
        if ((exists(outputFile))) {
            remove(outputFile, recursive: true)
        }
        try (file = File(outputFile, OpenMode.ReadWrite)) {
            let outputStream = BufferedOutputStream<File>(file, 8192 * 2)
            var readLength = inputStream.read(buff)
            while (readLength > 0) {
                outputStream.write(buff[0..readLength])
                progressMonitor.updateWorkCompleted(readLength)
                verifyIfTaskIsCancelled()
                readLength = inputStream.read(buff)
            }
            outputStream.flush()
        } catch (e: Exception) {
            if (exists(outputFile)) {
                remove(outputFile, recursive: true)
            }
            throw e
        }
    }

    private func createSymLink(
        zipInputStream: ZipInputStream,
        fileHeader: FileHeader,
        outputFile: Path,
        outputRoot: Path,
        progressMonitor: ProgressMonitor,
        readBuff: Array<Byte>
    ) {
        let symLinkPathBuff = readSymLink(zipInputStream, fileHeader, progressMonitor, readBuff)
        if (!exists(outputFile.parent)) {
            Directory.create(outputFile.parent, recursive: true)
        }
        if (getPlatformWindows()) {
            // Windows 不支持符号链接, 降级为普通文件保存链接目标路径(与 zip4j 行为一致)
            if (exists(outputFile)) {
                remove(outputFile)
            }
            try (file = File(outputFile, OpenMode.ReadWrite)) {
                file.write(symLinkPathBuff)
            }
            return
        }
        createSymbolicLinkAt(symLinkPathBuff, outputFile, outputRoot)
    }

    private func readSymLink(
        zipInputStream: ZipInputStream,
        fileHeader: FileHeader,
        progressMonitor: ProgressMonitor,
        readBuff: Array<Byte>
    ): Array<Byte> {
        let declaredSize = fileHeader.getUncompressedSize()
        // 符号链接目标路径不会很长, 声明尺寸来自不可信的压缩包头, 异常时直接拒绝以防内存放大
        if (declaredSize < 0 || declaredSize > MAX_SYMLINK_TARGET_SIZE) {
            throw ZipException("Invalid symbolic link entry size: ${declaredSize}")
        }
        let symLinkPathBuff = Array<Byte>(declaredSize, repeat: 0)
        var offset: Int64 = 0
        var readLength: Int64 = zipInputStream.read(readBuff)
        while (readLength > 0) {
            // 实际数据超过声明尺寸(损坏/恶意包)时拒绝, 避免写越界
            if (offset + readLength > declaredSize) {
                throw ZipException("Symbolic link entry data exceeds declared size")
            }
            readBuff[0..readLength].copyTo(symLinkPathBuff, 0, offset, readLength)
            progressMonitor.updateWorkCompleted(readLength)
            offset += readLength
            readLength = zipInputStream.read(readBuff)
        }
        // 按实际读取长度返回, 避免尾部补零字节混入链接目标
        return symLinkPathBuff[0..offset]
    }

    private func verifyNextEntry(zipInputStream: ZipInputStream, fileHeader: FileHeader) {
        if (BitUtils.isBitSet(fileHeader.getGeneralPurposeFlag().getOrThrow()[0], 6)) {
            throw ZipException(
                "Entry with name ${fileHeader.getFileName()} is encrypted with Strong Encryption. Zip4j does not support Strong Encryption, as this is patented."
            )
        }
        var localFileHeader = zipInputStream.getNextEntry(fileHeader, false)
        if (localFileHeader.isNone()) {
            throw ZipException(
                "Could not read corresponding local file header for file header: ${fileHeader.getFileName()}")
        }

        if (!(fileHeader.getFileName() == (localFileHeader.getOrThrow().getFileName()))) {
            throw ZipException("File header and local file header mismatch")
        }
    }

    // TODO check Output Directory Structure
    private func checkOutputDirectoryStructure(outputFile: Path) {
        outputFile
        return
    }

    private func determineOutputFile(fileHeader: FileHeader, outputPath: String, newFileName: ?String): Path {
        var outputFileName = fileHeader.getFileName() ?? ""
        if (Zip4cjUtil.isStringNotNullAndNotEmpty(newFileName)) {
            outputFileName = newFileName.getOrThrow()
        }
        if (!exists(outputPath)) {
            Directory.create(outputPath)
        }
        return Path(outputPath).join(getFileNameWithSystemFileSeparators(outputFileName))
    }

    private func getFileNameWithSystemFileSeparators(fileNameToReplace: String): String {
        return fileNameToReplace.replace(":\\\\", "_").replace("/", Path.Separator).replace("\\\\", Path.Separator)
    }

    protected func getTask(): ProgressMonitorTask {
        return ProgressMonitorTask.EXTRACT_ENTRY
    }

    public func getZipModel(): ZipModel {
        return zipModel
    }
}

@When[os != "Windows"]
func createSymbolicLinkAt(symLinkPathBuff: Array<Byte>, outputFile: Path, outputRoot: Path) {
    var symLinkPath = ""
    try {
        symLinkPath = String.fromUtf8(symLinkPathBuff)
    } catch (e: Exception) {
        throw ZipException("Symbolic link target is not valid UTF-8")
    }
    if (isSymbolicLinkTargetEscaping(symLinkPath, outputFile, outputRoot)) {
        throw ZipException(
            "Symbolic link target escapes the extraction directory: ${outputFile} -> ${symLinkPath}")
    }
    if (exists(outputFile)) {
        remove(outputFile)
    }
    if (symlink(symLinkPath, outputFile.toString()) != 0) {
        throw ZipException("Could not create symlink: ${outputFile} -> ${symLinkPath}")
    }
}

@When[os == "Windows"]
func createSymbolicLinkAt(symLinkPathBuff: Array<Byte>, outputFile: Path, outputRoot: Path) {
    // 上层 createSymLink 已按平台降级为普通文件, 正常不会走到此分支;
    // 保留占位以满足 Windows 编译期的符号解析, 若运行时分派失效则显式报错而非静默跳过
    throw ZipException("Current platform does not support symbolic links")
}

// Zip Slip via Symlink 防护: 链接目标来自不可信的压缩包内容, 创建前校验其不会
// 让后续条目写入逃逸出解压根目录:
// 1. 拒绝绝对路径目标;
// 2. 相对目标从 outputFile.parent(位于解压根之下)出发虚拟解析, 处理 "." / ".." 段,
//    深度回退越过解压根即视为逃逸
func isSymbolicLinkTargetEscaping(symLinkPath: String, outputFile: Path, outputRoot: Path): Bool {
    if (symLinkPath.startsWith(Path.Separator)) {
        return true
    }
    let rootCanonical = canonicalize(outputRoot).toString()
    let parentCanonical = canonicalize(outputFile.parent).toString()
    if (parentCanonical != rootCanonical &&
        !parentCanonical.startsWith("${rootCanonical}${Path.Separator}")) {
        // outputFile 本身不在解压根之下(异常场景), 保守拒绝
        return true
    }
    var depth = pathSegmentCount(parentCanonical) - pathSegmentCount(rootCanonical)
    for (seg in symLinkPath.replace("\\\\", "/").split("/")) {
        if (seg == "" || seg == ".") {
            continue
        }
        if (seg == "..") {
            depth -= 1
            if (depth < 0) {
                return true
            }
        } else {
            depth += 1
        }
    }
    return false
}

func pathSegmentCount(path: String): Int64 {
    var count: Int64 = 0
    for (seg in path.split(Path.Separator)) {
        if (seg != "") {
            count += 1
        }
    }
    return count
}
