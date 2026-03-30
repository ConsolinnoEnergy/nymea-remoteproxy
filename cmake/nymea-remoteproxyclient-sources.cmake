# CMake module that populates source lists for nymea-remoteproxyclient.
# Consumed by libnymea-app/CMakeLists.txt.

set(_rpc_dir "${CMAKE_CURRENT_LIST_DIR}/../libnymea-remoteproxyclient")
set(_common_dir "${CMAKE_CURRENT_LIST_DIR}/../common")

function(nymea_remoteproxyclient_sources out_sources out_headers out_include_dirs)
    file(GLOB _sources CONFIGURE_DEPENDS "${_rpc_dir}/*.cpp")
    file(GLOB _headers CONFIGURE_DEPENDS "${_rpc_dir}/*.h")
    file(GLOB _tp_sources CONFIGURE_DEPENDS "${_rpc_dir}/tunnelproxy/*.cpp")
    file(GLOB _tp_headers CONFIGURE_DEPENDS "${_rpc_dir}/tunnelproxy/*.h")
    file(GLOB _common_sources CONFIGURE_DEPENDS "${_common_dir}/*.cpp")
    file(GLOB _common_headers CONFIGURE_DEPENDS "${_common_dir}/*.h")

    list(APPEND _sources ${_tp_sources} ${_common_sources})
    list(APPEND _headers ${_tp_headers} ${_common_headers})

    set(${out_sources} ${_sources} PARENT_SCOPE)
    set(${out_headers} ${_headers} PARENT_SCOPE)
    set(${out_include_dirs}
        "${_rpc_dir}"
        "${_rpc_dir}/tunnelproxy"
        "${_common_dir}"
        PARENT_SCOPE
    )
endfunction()
