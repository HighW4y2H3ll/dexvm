cmake_minimum_required (VERSION 3.0)
project (dexvm)

include_directories ("${PROJECT_SOURCE_DIR}/../dalvik")
include_directories ("${PROJECT_SOURCE_DIR}/../includes")

add_library (libdex OBJECT
    ${PROJECT_SOURCE_DIR}/../dalvik/libdex/CmdUtils.cpp
    ${PROJECT_SOURCE_DIR}/../dalvik/libdex/DexCatch.cpp
	${PROJECT_SOURCE_DIR}/../dalvik/libdex/DexClass.cpp
	${PROJECT_SOURCE_DIR}/../dalvik/libdex/DexDataMap.cpp
	${PROJECT_SOURCE_DIR}/../dalvik/libdex/DexDebugInfo.cpp
	${PROJECT_SOURCE_DIR}/../dalvik/libdex/DexFile.cpp
	${PROJECT_SOURCE_DIR}/../dalvik/libdex/DexInlines.cpp
	${PROJECT_SOURCE_DIR}/../dalvik/libdex/DexOptData.cpp
	${PROJECT_SOURCE_DIR}/../dalvik/libdex/DexOpcodes.cpp
	${PROJECT_SOURCE_DIR}/../dalvik/libdex/DexProto.cpp
	${PROJECT_SOURCE_DIR}/../dalvik/libdex/DexSwapVerify.cpp
	${PROJECT_SOURCE_DIR}/../dalvik/libdex/DexUtf.cpp
	${PROJECT_SOURCE_DIR}/../dalvik/libdex/InstrUtils.cpp
	${PROJECT_SOURCE_DIR}/../dalvik/libdex/Leb128.cpp
	${PROJECT_SOURCE_DIR}/../dalvik/libdex/OptInvocation.cpp
	${PROJECT_SOURCE_DIR}/../dalvik/libdex/sha1.cpp
	${PROJECT_SOURCE_DIR}/../dalvik/libdex/SysUtil.cpp
	${PROJECT_SOURCE_DIR}/../dalvik/libdex/ZipArchive.cpp
    )

add_definitions (-DHAVE_POSIX_FILEMAP=1)

add_executable (dexvm main.cc)
target_link_libraries (dexvm libdex z)
