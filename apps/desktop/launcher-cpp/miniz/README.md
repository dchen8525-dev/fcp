# vendored miniz 3.0.2

richgel999/miniz 发行包（3.0.2 release zip）原样 vendored：amalgamated
形态（miniz.c 全量实现 + miniz.h），外加由本工程持有的 `miniz_export.h`
（upstream 设计为由其 CMake 生成，tarball 不带；本工程静态编译，只需
`MINIZ_EXPORT` 展开为空）。

唯一来源：https://github.com/richgel999/miniz/releases/tag/3.0.2
校验（sha256，byte-identical）：见 src 侧 ChangeLog。

剪裁由 CMake 提供 `MINIZ_NO_ARCHIVE_WRITING_APIS`（只读 zip）。其余剪裁宏
不可用：amalgamated 的 zip 段包在 `MINIZ_NO_ARCHIVE_APIS` 里、
`extract_to_file` 走 `MZ_FOPEN`。
