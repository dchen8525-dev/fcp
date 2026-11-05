/* Vendored 随附文件：upstream（richgel999/miniz 3.0.2）把 miniz_export.h 设
 * 计为由其 CMake 生成的导出宏头，分发 tarball 里没有。本工程是单一子目录
 * 静态编译（launcher 的 add_executable 直接吃 miniz*.c），不存在 DLL 导出，
 * 因此该头只需把 MINIZ_EXPORT 展开为空。 */
#ifndef MINIZ_EXPORT_H
#define MINIZ_EXPORT_H

#define MINIZ_EXPORT

#endif /* MINIZ_EXPORT_H */
