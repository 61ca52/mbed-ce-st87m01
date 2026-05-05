add_library(st87m01 INTERFACE)

target_include_directories(st87m01
    INTERFACE
        include
        include/st87m01
)

target_sources(st87m01
    INTERFACE
        src/ST87M01.cpp
        src/ST87M01_CellularContext.cpp
        src/ST87M01_CellularInformation.cpp
        src/ST87M01_CellularNetwork.cpp
        src/ST87M01_CellularStack.cpp
        src/ST87M01_HTTP.cpp
        src/ST87M01_TlsProvisioning.cpp
)

target_link_libraries(st87m01
    INTERFACE
    mbed-core-flags
    mbed-cellular
)