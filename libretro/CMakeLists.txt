
set(LIBRETRO_SRCS
	libretro.cpp
	LibretroGraphicsContext.cpp
	LibretroGLContext.cpp
	LibretroGLCoreContext.cpp
	LibretroVulkanContext.cpp
	LibretroVulkanPresentation.cpp)

if(WIN32)
	set(LIBRETRO_SRCS ${LIBRETRO_SRCS}
		LibretroD3D11Context.cpp)
endif()

set(LIBRETRO_SRCS ${LIBRETRO_SRCS}
	libretro-common/compat/compat_posix_string.c
	libretro-common/compat/fopen_utf8.c
	libretro-common/compat/compat_strl.c
	libretro-common/encodings/encoding_utf.c
	libretro-common/file/file_path.c
	libretro-common/file/file_path_io.c
	libretro-common/streams/file_stream.c
	libretro-common/streams/file_stream_transforms.c
	libretro-common/string/stdstring.c
	libretro-common/time/rtime.c
	libretro-common/vfs/vfs_implementation.c)

include_directories(libretro)

add_library(ppsspp_libretro SHARED ${LIBRETRO_SRCS})
set(LIBRARY_OUTPUT_PATH "${CMAKE_BINARY_DIR}")
set_target_properties(ppsspp_libretro PROPERTIES PREFIX "")
if(ANDROID)
	set_target_properties(ppsspp_libretro PROPERTIES SUFFIX "_android.so")
endif()
target_include_directories(ppsspp_libretro PRIVATE libretro-common/include)

if(NOT MSVC)
   if (APPLE OR IOS)
   	target_link_libraries(ppsspp_libretro objc "-Wl,-exported_symbols_list,${CMAKE_CURRENT_SOURCE_DIR}/libretro.osx.def")
   else()
   	target_link_libraries(ppsspp_libretro "-Wl,-Bsymbolic")
   endif()
endif()
if(APPLE AND NOT IOS)
   # HTTPS::LoadDefaultCerts() walks the macOS trust store (Security + CF).
   # The app targets get these via nativeExtraLibs; the libretro dylib links
   # Core directly, so it needs them itself. macOS-only - the cert code is
   # compiled out on iOS (TARGET_OS_OSX guard in Core/Net/HTTPS.cpp).
   target_link_libraries(ppsspp_libretro "-framework Security" "-framework CoreFoundation")
endif()
target_link_libraries(ppsspp_libretro Core ${CMAKE_THREAD_LIBS_INIT})
if(ANDROID)
	target_link_libraries(ppsspp_libretro log)
endif()
