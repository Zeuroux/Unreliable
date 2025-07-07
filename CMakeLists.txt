cmake_policy(SET CMP0077 NEW)
cmake_minimum_required(VERSION 3.22.1)
project(Unreliable LANGUAGES C CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF)

if(MINGW OR WIN32)
  set(OPT_FLAGS
      -Ofast
      -march=native
      -mtune=native
      -flto=8
      -fuse-linker-plugin
      -fwhole-program
      -fno-semantic-interposition
      -ffast-math
      -funsafe-math-optimizations
      -fno-math-errno
      -fno-signed-zeros
      -fno-trapping-math
      -fno-rounding-math
      -funroll-loops
      -ftree-vectorize
      -finline-functions
      -fstrict-aliasing
      -fipa-pta
      -fipa-cp
      -fomit-frame-pointer
      -fno-stack-protector
      -falign-functions=32
      -falign-loops=16
      -ffunction-sections
      -fdata-sections
      -DNDEBUG
  )

  string(REPLACE ";" " " OPT_FLAGS_STR "${OPT_FLAGS}")

  set(CMAKE_CXX_FLAGS_RELEASE "${CMAKE_CXX_FLAGS_RELEASE} ${OPT_FLAGS_STR} -fno-rtti")
  set(CMAKE_C_FLAGS_RELEASE "${CMAKE_C_FLAGS_RELEASE} ${OPT_FLAGS_STR}")

  set(CMAKE_EXE_LINKER_FLAGS_RELEASE "${CMAKE_EXE_LINKER_FLAGS_RELEASE} \
      -flto=8 \
      -fuse-linker-plugin \
      -Wl,--gc-sections \
      -Wl,-O1 \
      -Wl,--sort-section=alignment \
      -s")
endif()

set(BUILD_SHARED_LIBS OFF)
set(BUILD_COMMAND_LINE_TOOLS OFF)
set(ZYAN_WHOLE_PROGRAM_OPTIMIZATION ON)

include(FetchContent)

FetchContent_Declare(
  elfio
  GIT_REPOSITORY https://github.com/serge1/ELFIO
  GIT_TAG        main
)

FetchContent_Declare(
  pe-parse
  GIT_REPOSITORY https://github.com/Zeuroux/pe-parse
  GIT_TAG        master
)

FetchContent_Declare(
  Zydis
  GIT_REPOSITORY https://github.com/zyantific/zydis.git
  GIT_TAG        master
)

FetchContent_MakeAvailable(elfio pe-parse Zydis)

add_library(Unreliable STATIC
    src/unreliable.cpp
    src/parser.cpp
    src/decoders/arm64.cpp
    src/utils/searchers.cpp
)
target_link_options(Unreliable PRIVATE "-static")
target_include_directories(Unreliable
  PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/src>
    $<INSTALL_INTERFACE:include>
)

target_link_libraries(Unreliable PRIVATE elfio pe-parse::pe-parse Zydis::Zydis)

enable_testing()
add_executable(tests tests/test.cpp)
target_link_options(tests PRIVATE "-static")
target_link_libraries(tests PRIVATE Unreliable)
add_test(NAME tests COMMAND tests ../testing/android_client_arm64.so)